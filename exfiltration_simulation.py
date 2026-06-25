"""
SimPy Discrete-Event Simulation for MTD (Moving Target Defense)
Application: Container Migration & Data Exfiltration

Run example:
	python exfiltration_simulation.py --runtime 3600 --arrival-rate 0.01 --output results.json

This script models containers that can be exfiltrated by arriving attackers.
Containers are migrated periodically (MTD). Migrations are chosen randomly
and are stateful: exfiltration progress persists across migrations.
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
from typing import List, Optional
import logging

import simpy


class Node:
	"""Represents a physical node hosting containers."""
	def __init__(self, node_id: int):
		self.node_id = node_id
		self.infection_level = 0.0  # ranges from 0.0 (clean) upwards
		self.last_decay_time = 0.0  # track when we last decayed infection


class Tenant:
	"""Represents a tenant running a microservice application."""
	def __init__(self, tenant_id: int, is_malicious: bool = False):
		self.tenant_id = tenant_id
		self.is_malicious = is_malicious
		self.containers: List[Container] = []
		self.total_exfiltrated = 0.0


class Container:
	def __init__(self, cid: int, max_data: float, container_type: str, component_name: str, 
	             migration_times: dict, priority: int, tenant: Tenant, node: Optional[Node] = None):
		self.cid = cid
		self.container_type = container_type  # e.g., 'back_end', 'front_end', 'database'
		self.component_name = component_name  # e.g., 'back_end'
		self.migration_times = migration_times  # dict with keys: cold, pre_copy, post_copy, hybrid
		self.priority = priority  # 0=CRITICAL, 1=HIGH, 2=MEDIUM, 3=LOW
		self.tenant = tenant
		self.node = node
		self.max_data = float(max_data)
		self.exfiltrated = 0.0
		self.migrating = False
		self.fully_exfiltrated_time: Optional[float] = None
		self.lock: Optional[simpy.Resource] = None  # Will be set after env creation
		# Attacker preparation tracking
		self.attacker_prepared: dict = {}  # Maps attacker_id -> preparation_complete_time
		self.last_attacked_time: Optional[float] = None  # Track when last actively attacked for decay

	def is_full(self) -> bool:
		return self.exfiltrated >= self.max_data


def malicious_tenant_attacker(env: simpy.Environment, malicious_tenant: Tenant, victim_containers: List[Container], 
                              params: dict, metrics: dict, logger, attacker_rng):
	"""
	Continuous attacker process for malicious tenant.
	Monitors co-location and attacks victim containers on same nodes.
	Requires preparation time before starting exfiltration on new targets.
	"""
	attacker_id = malicious_tenant.tenant_id
	step = params['time_step']
	
	# Track which single victim the attacker is currently focused on
	current_target_cid: Optional[int] = None
	
	while env.now < params['runtime']:
		# Find nodes where malicious tenant has containers
		malicious_nodes = set(c.node for c in malicious_tenant.containers if c.node is not None)
		
		# Find victim containers on same nodes (co-located), not yet fully exfiltrated
		colocated_victims = [c for c in victim_containers if c.node in malicious_nodes and not c.is_full()]
		
		if not colocated_victims:
			# No eligible victims this step
			current_target_cid = None
			yield env.timeout(step)
			continue
		
		# If the current focused target is no longer eligible (migrated away, fully exfiltrated,
		# or no longer co-located), the attacker must pick a new one
		colocated_cids = {c.cid for c in colocated_victims}
		if current_target_cid not in colocated_cids:
			# Pick a new single target randomly from the co-located eligible victims
			victim = attacker_rng.choice(colocated_victims)
			current_target_cid = victim.cid
			logger.info(
				"Attacker (tenant %d) switched focus to container %d (tenant %d) at %.2f",
				attacker_id,
				victim.cid,
				victim.tenant.tenant_id,
				env.now,
			)
		else:
			victim = next(c for c in colocated_victims if c.cid == current_target_cid)
		
		# --- Work on the single focused victim ---
		
		# Check if we need preparation time for this victim
		if attacker_id not in victim.attacker_prepared:
			prep_time = max(1.0, attacker_rng.gauss(params['preparation_time_mean'], params['preparation_time_std']))
			logger.info(
				"Attacker (tenant %d) starting preparation for container %d (tenant %d) at %.2f, prep_time=%.2f",
				attacker_id,
				victim.cid,
				victim.tenant.tenant_id,
				env.now,
				prep_time,
			)
			victim.attacker_prepared[attacker_id] = env.now + prep_time
			# Spend this step preparing — attacker wholly occupied
			yield env.timeout(step)
			continue
		
		# Still preparing for this target
		if env.now < victim.attacker_prepared[attacker_id]:
			yield env.timeout(step)
			continue
		
		# Preparation complete — attempt exfiltration on this single target
		if victim.migrating:
			# Target is migrating; attacker loses focus and will re-pick next step
			logger.debug(
				"Attacker (tenant %d) lost target container %d to migration at %.2f",
				attacker_id,
				victim.cid,
				env.now,
			)
			current_target_cid = None
			yield env.timeout(step)
			continue
		
		# Acquire lock and exfiltrate from the single focused target
		with victim.lock.request() as req:
			result = yield req | env.timeout(step)
			if req not in result:
				# Couldn't get lock (migration won the race) — lose focus
				current_target_cid = None
				continue
			
			if victim.migrating or victim.is_full():
				current_target_cid = None
				continue
			
			# Calculate capability based on node infection
			base_capability = params['capability_mean']
			infection_multiplier = 1.0 + (victim.node.infection_level * params['infection_impact']) if victim.node else 1.0
			capability = base_capability * infection_multiplier
			
			# Exfiltrate for one time step
			amount_needed = victim.max_data - victim.exfiltrated
			time_to_finish = amount_needed / capability if capability > 0 else float('inf')
			t = min(step, time_to_finish)
			exf = capability * t
			
			# Increase node infection
			if victim.node:
				infection_increase = params['infection_rate'] * exf
				victim.node.infection_level += infection_increase
			
			victim.exfiltrated += exf
			if victim.exfiltrated > victim.max_data:
				victim.exfiltrated = victim.max_data
			
			victim.last_attacked_time = env.now
			
			# Record completion
			if victim.is_full() and victim.fully_exfiltrated_time is None:
				victim.fully_exfiltrated_time = env.now
				logger.info(
					"Container %d (tenant %d, priority %d) fully exfiltrated at %.2f",
					victim.cid,
					victim.tenant.tenant_id,
					victim.priority,
					env.now,
				)
				# Target fully exfiltrated — attacker will pick a new one next step
				current_target_cid = None
			
			logger.debug(
				"Attacker (tenant %d) exfiltrated %.3f from container %d (tenant %d, priority %d) at %.2f (total %.3f)",
				attacker_id,
				exf,
				victim.cid,
				victim.tenant.tenant_id,
				victim.priority,
				env.now,
				victim.exfiltrated,
			)
		
		# One full time step spent on this single target
		yield env.timeout(step)


def exfiltration_decay_process(env: simpy.Environment, containers: List[Container], params: dict, logger):
	"""
	Decay exfiltrated data when container is not actively being attacked.
	This represents the container's data state changing over time, making old stolen data less valuable.
	"""
	decay_step = 10.0  # Check every 10 seconds
	
	while env.now < params['runtime']:
		yield env.timeout(decay_step)
		
		for container in containers:
			if container.exfiltrated > 0 and container.last_attacked_time is not None:
				time_since_attack = env.now - container.last_attacked_time
				
				# Only decay if not recently attacked (grace period of decay_step)
				if time_since_attack >= decay_step:
					# Exponential decay
					decay_factor = (1.0 - params['exfiltration_decay_rate']) ** (time_since_attack / decay_step)
					old_exfiltrated = container.exfiltrated
					container.exfiltrated *= decay_factor
					
					if old_exfiltrated - container.exfiltrated > 0.01:  # Log only significant decay
						logger.debug(
							"Container %d (tenant %d) exfiltration decayed from %.3f to %.3f (inactive for %.1fs)",
							container.cid,
							container.tenant.tenant_id,
							old_exfiltrated,
							container.exfiltrated,
							time_since_attack,
						)


def select_migration_method(container: Container, method_policy: str) -> str:
	"""Select which migration method to use based on policy."""
	if method_policy == "always_precopy":
		return "pre_copy"
	elif method_policy == "always_cold":
		return "cold"
	elif method_policy == "min_time":
		# Choose the method with minimum migration time for this container type
		return min(container.migration_times.keys(), key=lambda m: container.migration_times[m])
	else:
		return "pre_copy"  # default


def choose_container_to_migrate(containers: List[Container], policy: str, rng: random.Random) -> Container:
	if policy == "random":
		return rng.choice(containers)
	elif policy == "highest_progress":
		return max(containers, key=lambda c: c.exfiltrated / c.max_data)
	elif policy == "in_most_infected_cluster":  # Now interpreted as "in_most_infected_node"
		return max(containers, key=lambda c: c.node.infection_level if c.node else 0.0)
	elif policy == "priority_based":
		# Prefer higher priority containers (lower priority number = higher importance)
		# Weight by priority: 0=CRITICAL gets 4x weight, 1=HIGH gets 3x, 2=MEDIUM gets 2x, 3=LOW gets 1x
		weights = {0: 4.0, 1: 3.0, 2: 2.0, 3: 1.0}
		container_weights = [weights.get(c.priority, 1.0) for c in containers]
		return rng.choices(containers, weights=container_weights, k=1)[0]
	else:
		return rng.choice(containers)  # default to random


def calculate_avg_migration_time(containers: List[Container], method_policy: str) -> float:
	"""Calculate expected average migration time based on method policy."""
	if method_policy == "always_precopy":
		# Average of all pre_copy times across all containers
		times = [c.migration_times.get("pre_copy", 0) for c in containers]
		return sum(times) / len(times) if times else 10.0
	elif method_policy == "always_cold":
		# Average of all pre_copy times across all containers
		times = [c.migration_times.get("cold", 15) for c in containers]
		return sum(times) / len(times) if times else 10.0
	elif method_policy == "min_time":
		# Average of minimum migration times for each container
		min_times = [min(c.migration_times.values()) for c in containers]
		return sum(min_times) / len(min_times) if min_times else 5.0
	else:
		# For other policies, compute overall average
		all_times = []
		for c in containers:
			all_times.extend(c.migration_times.values())
		return sum(all_times) / len(all_times) if all_times else 10.0


def infection_decay_process(env: simpy.Environment, nodes: List[Node], params: dict, logger):
	"""Continuously decay infection levels on all nodes over time."""
	decay_step = 10.0  # decay every 10 seconds
	while env.now < params['runtime']:
		yield env.timeout(decay_step)
		for node in nodes:
			time_elapsed = env.now - node.last_decay_time
			if node.infection_level > 0:
				# Exponential decay: infection_level *= exp(-decay_rate * time)
				decay_factor = (1.0 - params['infection_decay_rate']) ** (time_elapsed / decay_step)
				old_level = node.infection_level
				node.infection_level *= decay_factor
				logger.debug(
					"Node %d infection decayed from %.4f to %.4f at %.2f",
					node.node_id,
					old_level,
					node.infection_level,
					env.now,
				)
			node.last_decay_time = env.now


def migration_scheduler(env: simpy.Environment, containers: List[Container], params: dict, metrics: dict, nodes: List[Node], logger, migration_rng):
	# Calculate migration period automatically based on runtime, time budget, and expected migration time
	if params.get('auto_migration_period', True):
		# Estimate average migration time based on policy
		avg_migration_time = calculate_avg_migration_time(containers, params['migration_method_policy'])
		# Calculate how many migrations can fit in the time budget
		expected_migrations = params['time_budget'] / avg_migration_time if avg_migration_time > 0 else 1
		# Distribute them evenly across runtime with 10% jitter for realism
		migration_period = params['runtime'] / max(1, expected_migrations)
		logger.info(
			"Auto-calculated migration period: %.2f (avg migration time: %.2f, expected migrations: %.1f)",
			migration_period,
			avg_migration_time,
			expected_migrations,
		)
	else:
		migration_period = params['migration_period']
		logger.info("Using manual migration period: %.2f", migration_period)
	
	# Start first migration immediately
	if params['runtime'] > 0:
		chosen = choose_container_to_migrate(containers, params['migration_policy'], migration_rng)
		env.process(migrate_container(env, chosen, params, metrics, nodes, logger, migration_rng))

	while env.now < params['runtime']:
		# Add small jitter (±10%) to migration period for realism
		jitter_factor = migration_rng.uniform(0.9, 1.1)
		yield env.timeout(migration_period * jitter_factor)
		if env.now >= params['runtime']:
			break
		chosen = choose_container_to_migrate(containers, params['migration_policy'], migration_rng)
		env.process(migrate_container(env, chosen, params, metrics, nodes, logger, migration_rng))


def migrate_container(env: simpy.Environment, container: Container, params: dict, metrics: dict, nodes: List[Node], logger, migration_rng):
	# Check time budget - only allow migration if budget is still positive
	# Once migration starts, it can push budget negative, but no new migrations if already negative
	if metrics['time_budget_remaining'] <= 0:
		logger.info("Migration time budget exhausted at %.2f, skipping migration for container %d", env.now, container.cid)
		return
	
	# Select migration method based on policy
	method = select_migration_method(container, params['migration_method_policy'])
	mean_migration_time = container.migration_times[method]
	
	# Add realistic variation to migration time using normal distribution
	# Standard deviation is 15% of mean to capture variance in migration performance
	std_dev = mean_migration_time * 0.15
	# Ensure migration time is positive (use max with small minimum value)
	migration_time = max(0.1, migration_rng.gauss(mean_migration_time, std_dev))
	
	# Subtract actual migration time from budget (can go negative)
	metrics['time_budget_remaining'] -= migration_time
	metrics['migrations'] += 1
	metrics['total_migration_time'] += migration_time
	
	old_node = container.node
	logger.info(
		"Migration start for container %d (tenant %d, %s) at %.2f using %s method (duration %.2f) from node %d",
		container.cid,
		container.tenant.tenant_id,
		container.container_type,
		env.now,
		method,
		migration_time,
		old_node.node_id if old_node else -1,
	)
	container.migrating = True
	yield env.timeout(migration_time)
	
	# Migration disrupts attackers: roll back some exfiltration progress
	# This represents data reset/cleanup during migration process
	rollback_percentage = params.get('migration_rollback', 0.10)  # Default 10% rollback
	if container.exfiltrated > 0:
		old_exfiltrated = container.exfiltrated
		container.exfiltrated = max(0, container.exfiltrated * (1.0 - rollback_percentage))
		logger.info(
			"Migration rollback: container %d exfiltration reduced from %.2f to %.2f (%.1f%% rollback)",
			container.cid,
			old_exfiltrated,
			container.exfiltrated,
			rollback_percentage * 100,
		)
	
	# Reset attacker preparation - they need to re-prepare for this container at new location
	if container.attacker_prepared:
		logger.info(
			"Migration reset attacker preparation for container %d (had %d prepared attackers)",
			container.cid,
			len(container.attacker_prepared),
		)
		container.attacker_prepared.clear()
	
	# Move container to a less-loaded node (load balancing + malicious tenant avoidance)
	# Count containers per node and select one with minimum count
	if nodes:
		node_loads = {n: sum(1 for cont in metrics['container_objects'] if cont.node == n) for n in nodes}
		
		# Security-aware migration: If this is a victim container, avoid nodes with malicious tenant
		nodes_to_avoid = {old_node}  # Always avoid current node
		
		# Nice Idea Copilot, but the defender doesn't actually know which tenant is malicious in a real scenario
		# so we can't directly check container.tenant.is_malicious here.
		# if not container.tenant.is_malicious:
		# 	# Find all nodes where malicious tenant has containers
		# 	malicious_nodes = {c.node for c in metrics['container_objects'] 
		# 	                  if c.tenant.is_malicious and c.node is not None}
		# 	nodes_to_avoid.update(malicious_nodes)
		# 	logger.info(
		# 		"Container %d (victim) avoiding %d nodes with malicious tenant: %s",
		# 		container.cid,
		# 		len(malicious_nodes),
		# 		{n.node_id for n in malicious_nodes} if malicious_nodes else set(),
		# 	)
		
		# Try to find safe nodes (not avoided)
		available_nodes = [n for n in nodes if n not in nodes_to_avoid]
		
		# Fallback: if all nodes have malicious tenant, use least-loaded excluding current
		if not available_nodes:
			logger.warning("No safe nodes available for container %d - using least-loaded fallback", container.cid)
			available_nodes = [n for n in nodes if n != old_node]
		
		# Final fallback: if only one node total, reuse it
		if not available_nodes:
			available_nodes = nodes
		
		# Choose least-loaded node among available ones (ties broken randomly)
		min_load = min(node_loads[n] for n in available_nodes)
		candidates = [n for n in available_nodes if node_loads[n] == min_load]
		container.node = migration_rng.choice(candidates)
		logger.info(
			"Selected node %d (load: %d) from %d candidates with loads: %s",
			container.node.node_id,
			node_loads[container.node],
			len(candidates),
			{n.node_id: node_loads[n] for n in available_nodes},
		)
		
	container.migrating = False
	logger.info(
		"Migration end for container %d at %.2f to node %d",
		container.cid,
		env.now,
		container.node.node_id if container.node else -1,
	)


def run_simulation(args):
	# configure logging
	logger = logging.getLogger('exfiltration_simulation')
	# remove existing handlers
	for h in list(logger.handlers):
		logger.removeHandler(h)
	level = getattr(logging, args.log_level.upper(), logging.INFO)
	logger.setLevel(level)
	fh = logging.FileHandler(args.log_file)
	fh.setLevel(level)
	fmt = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
	fh.setFormatter(fmt)
	logger.addHandler(fh)
	# keep console warnings/errors visible
	ch = logging.StreamHandler()
	ch.setLevel(logging.WARNING)
	ch.setFormatter(fmt)
	logger.addHandler(ch)
	
	# Load microservice configuration
	with open(args.config_file, 'r') as f:
		config = json.load(f)
	
	params = {
		'runtime': args.runtime,
		'preparation_time_mean': args.preparation_time_mean,
		'preparation_time_std': args.preparation_time_std,
		'capability_mean': args.capability_mean,
		'migration_period': args.migration_period,
		'auto_migration_period': args.auto_migration_period,
		'time_budget': args.time_budget,
		'migration_rollback': args.migration_rollback,
		'max_data_per_container': args.max_data_per_container,
		'time_step': args.time_step,
		'infection_rate': args.infection_rate,
		'infection_impact': args.infection_impact,
		'infection_decay_rate': args.infection_decay_rate,
		'exfiltration_decay_rate': args.exfiltration_decay_rate,
		'migration_policy': args.migration_policy,
		'migration_method_policy': args.migration_method_policy,
	}

	env = simpy.Environment()
	
	# Initialize physical nodes
	nodes = [Node(i) for i in range(args.num_nodes)]
	logger.info("Created %d physical nodes", len(nodes))
	
	# Create tenants (one will be malicious)
	tenants = []
	for tid in range(args.num_tenants):
		is_malicious = (tid == args.malicious_tenant_id)
		tenant = Tenant(tid, is_malicious)
		tenants.append(tenant)
		logger.info("Created tenant %d (malicious: %s)", tid, is_malicious)
	
	malicious_tenant = tenants[args.malicious_tenant_id]
	
	# Parse microservice application configuration
	# Expecting structure: config['applications']['sample-app']['components']
	app_name = list(config['applications'].keys())[0]  # Take first application
	components = config['applications'][app_name]['components']
	
	# Initialize containers for all tenants based on microservice template
	all_containers = []
	container_id = 0
	
	for tenant in tenants:
		logger.info("Instantiating microservice for tenant %d", tenant.tenant_id)
		for component_name, component_config in components.items():
			num_replicas = component_config['containers']  # Number of container instances
			migration_times = component_config['migration_time']
			migration_times.pop("stateless", None)  # Remove stateless migration time since it cannot be used in this simulation
			priority = component_config['priority']  # 0=CRITICAL, 1=HIGH, 2=MEDIUM, 3=LOW
			
			for replica in range(num_replicas):
				# Assign to node using round-robin initially
				assigned_node = nodes[container_id % len(nodes)] if nodes else None
				
				container = Container(
					container_id,
					params['max_data_per_container'],
					component_name,  # e.g., 'back_end', 'front_end'
					component_name,
					migration_times,
					priority,
					tenant,
					assigned_node
				)
				container.lock = simpy.Resource(env, capacity=1)
				all_containers.append(container)
				tenant.containers.append(container)
				container_id += 1
				
				logger.info(
					"  Created container %d: %s (tenant %d, node %d, priority %d)",
					container.cid,
					component_name,
					tenant.tenant_id,
					assigned_node.node_id if assigned_node else -1,
					priority,
				)
	
	logger.info("Total containers created: %d across %d tenants", len(all_containers), len(tenants))
	
	# Victim containers are all containers EXCEPT those belonging to malicious tenant
	victim_containers = [c for c in all_containers if c.tenant != malicious_tenant]
	logger.info("Victim containers: %d", len(victim_containers))

	metrics = {
		'migrations': 0,
		'time_budget_remaining': args.time_budget,
		'total_migration_time': 0.0,
		'container_objects': all_containers,  # Reference for load balancing during migration
	}

	# Create separate random generators for attackers and migrations
	# This ensures that different migration policies don't affect attacker behavior
	attacker_rng = random.Random(args.seed)
	migration_rng = random.Random(args.seed + 10000)

	# Start simulation processes
	env.process(malicious_tenant_attacker(env, malicious_tenant, victim_containers, params, metrics, logger, attacker_rng))
	env.process(migration_scheduler(env, all_containers, params, metrics, nodes, logger, migration_rng))
	env.process(infection_decay_process(env, nodes, params, logger))
	env.process(exfiltration_decay_process(env, all_containers, params, logger))

	env.run(until=params['runtime'])

	# finalize metrics
	total_exfil = sum(c.exfiltrated for c in all_containers)
	completion_times = [c.fully_exfiltrated_time for c in all_containers if c.fully_exfiltrated_time is not None]
	
	# Calculate weighted exfiltration score (priority-based penalty)
	# Priority 0 (CRITICAL) = 4x weight, 1 (HIGH) = 3x, 2 (MEDIUM) = 2x, 3 (LOW) = 1x
	priority_weights = {0: 4.0, 1: 3.0, 2: 2.0, 3: 1.0}
	weighted_exfiltration = sum(c.exfiltrated * priority_weights.get(c.priority, 1.0) for c in all_containers)
	
	# Per-tenant metrics
	tenant_metrics = []
	for tenant in tenants:
		tenant_total_exfil = sum(c.exfiltrated for c in tenant.containers)
		tenant_weighted_exfil = sum(c.exfiltrated * priority_weights.get(c.priority, 1.0) for c in tenant.containers)
		tenant_completed = sum(1 for c in tenant.containers if c.fully_exfiltrated_time is not None)
		tenant_completion_times = [c.fully_exfiltrated_time for c in tenant.containers if c.fully_exfiltrated_time is not None]
		
		# Per-priority breakdown
		priority_breakdown = {}
		for priority in [0, 1, 2, 3]:
			priority_containers = [c for c in tenant.containers if c.priority == priority]
			if priority_containers:
				priority_breakdown[priority] = {
					'count': len(priority_containers),
					'exfiltrated': sum(c.exfiltrated for c in priority_containers),
					'completed': sum(1 for c in priority_containers if c.fully_exfiltrated_time is not None),
				}
		
		tenant_metrics.append({
			'tenant_id': tenant.tenant_id,
			'is_malicious': tenant.is_malicious,
			'total_containers': len(tenant.containers),
			'total_exfiltrated': tenant_total_exfil,
			'weighted_exfiltration': tenant_weighted_exfil,
			'completed_containers': tenant_completed,
			'mean_completion_time': statistics.mean(tenant_completion_times) if tenant_completion_times else None,
			'priority_breakdown': priority_breakdown,
		})

	results = {
		'runtime': args.runtime,
		'num_tenants': args.num_tenants,
		'num_nodes': args.num_nodes,
		'num_containers': len(all_containers),
		'malicious_tenant_id': args.malicious_tenant_id,
		'migrations': metrics['migrations'],
		'total_exfiltrated': total_exfil,
		'weighted_exfiltration': weighted_exfiltration,
		'avg_exfiltration_rate': total_exfil / args.runtime if args.runtime > 0 else None,
		'container_completion_times': completion_times,
		'time_budget_remaining': metrics['time_budget_remaining'],
		'total_migration_time': metrics['total_migration_time'],
		'tenant_metrics': tenant_metrics,
		'containers': [
			{
				'cid': c.cid,
				'tenant_id': c.tenant.tenant_id,
				'container_type': c.container_type,
				'component_name': c.component_name,
				'priority': c.priority,
				'exfiltrated': c.exfiltrated,
				'max_data': c.max_data,
				'fully_exfiltrated_time': c.fully_exfiltrated_time,
				'node_id': c.node.node_id if c.node else None,
			}
			for c in all_containers
		],
		'nodes': [
			{
				'node_id': nd.node_id,
				'final_infection_level': nd.infection_level,
			}
			for nd in nodes
		],
		'params': params,
	}

	# write output
	if args.output:
		with open(args.output, 'w') as fh:
			json.dump(results, fh, indent=2)

	# print concise summary
	print(f"Runtime: {args.runtime}s")
	print(f"Tenants: {args.num_tenants} (malicious: tenant {args.malicious_tenant_id})")
	print(f"Nodes: {args.num_nodes}")
	print(f"Containers: {len(all_containers)}")
	print(f"Migrations: {metrics['migrations']}")
	print(f"Total migration time: {metrics['total_migration_time']:.2f}s")
	print(f"Time budget remaining: {metrics['time_budget_remaining']:.2f}s")
	print(f"Total exfiltrated: {total_exfil:.3f}")
	print(f"Weighted exfiltration (priority-based): {weighted_exfiltration:.3f}")
	
	print(f"\nPer-tenant results:")
	for tm in tenant_metrics:
		status = "(MALICIOUS)" if tm['is_malicious'] else "(victim)"
		print(f"  Tenant {tm['tenant_id']} {status}:")
		print(f"    Containers: {tm['total_containers']}")
		print(f"    Total exfiltrated: {tm['total_exfiltrated']:.3f}")
		print(f"    Weighted exfiltration: {tm['weighted_exfiltration']:.3f}")
		print(f"    Completed: {tm['completed_containers']}/{tm['total_containers']}")
		if tm['mean_completion_time']:
			print(f"    Mean completion time: {tm['mean_completion_time']:.2f}s")
		
		# Show priority breakdown
		if tm['priority_breakdown']:
			print(f"    Priority breakdown:")
			priority_names = {0: 'CRITICAL', 1: 'HIGH', 2: 'MEDIUM', 3: 'LOW'}
			for priority, data in sorted(tm['priority_breakdown'].items()):
				print(f"      {priority_names[priority]} (P{priority}): {data['exfiltrated']:.2f} exfiltrated, {data['completed']}/{data['count']} completed")
	
	if completion_times:
		print(f"\nOverall: {len(completion_times)} containers completed; mean time: {statistics.mean(completion_times):.2f}s")
	else:
		print("\nNo container was fully exfiltrated during the run.")

	return results


def parse_args():
	p = argparse.ArgumentParser()
	p.add_argument('--runtime', type=float, default=3600.0, help='Total simulation time (seconds)')
	p.add_argument('--preparation-time-mean', type=float, default=60.0, help='Mean time for attacker to prepare/observe before exfiltrating (seconds)')
	p.add_argument('--preparation-time-std', type=float, default=15.0, help='Standard deviation for preparation time (seconds)')
	p.add_argument('--capability-mean', type=float, default=0.1, help='Mean attacker exfiltration rate (data units per second)')
	p.add_argument('--migration-period', type=float, default=300.0, help='Period between migrations when auto mode disabled (seconds)')
	p.add_argument('--auto-migration-period', action='store_true', default=True, help='Automatically calculate migration period based on runtime and time budget')
	p.add_argument('--manual-migration-period', dest='auto_migration_period', action='store_false', help='Use manual migration period instead of auto-calculation')
	p.add_argument('--max-data-per-container', type=float, default=100.0, help='Maximum data that can be exfiltrated from a container (data units)')
	p.add_argument('--num-nodes', type=int, default=8, help='Number of physical nodes (recommended: ≥8 for effective security-aware migration)')
	p.add_argument('--num-tenants', type=int, default=3, help='Number of tenants (each runs the microservice application)')
	p.add_argument('--malicious-tenant-id', type=int, default=0, help='Which tenant is malicious (0-indexed)')
	p.add_argument('--config-file', type=str, default='/microservice-configs/default.json', help='Path to microservice configuration JSON file')
	p.add_argument('--infection-rate', type=float, default=0.01, help='Rate at which cluster infection increases per second of exfiltration')
	p.add_argument('--infection-impact', type=float, default=1.5, help='Multiplier impact of infection on exfiltration speed (e.g., 1.5 means 150%% speed boost per 1.0 infection, increased to make migration more valuable)')
	p.add_argument('--infection-decay-rate', type=float, default=0.01, help='Rate at which cluster infection decays per decay cycle (0.0-1.0, higher = faster decay, reduced to 0.01 to allow meaningful infection buildup)')
	p.add_argument('--exfiltration-decay-rate', type=float, default=0.05, help='Rate at which exfiltrated data decays when container is out of attacker reach (per decay cycle)')
	p.add_argument('--migration-policy', type=str, default='random', choices=['random', 'highest_progress', 'in_most_infected_cluster', 'priority_based'], help='Policy for selecting containers to migrate')
	p.add_argument('--migration-method-policy', type=str, default='always_precopy', choices=['always_precopy', 'always_cold', 'min_time'], help='Policy for selecting migration method: always_precopy (baseline) or always_cold or min_time')
	p.add_argument('--time-budget', type=float, default=1000.0, help='Total time budget for migrations (seconds)')
	p.add_argument('--migration-rollback', type=float, default=0.30, help='Percentage of exfiltration progress lost during migration (0.0-1.0, default 0.30 = 30%% rollback for security hardening)')
	p.add_argument('--time-step', type=float, default=1.0, help='Simulation time step for attacker progress (seconds)')
	p.add_argument('--output', type=str, default='simulation_results.json', help='Output JSON file path')
	p.add_argument('--seed', type=int, default=42, help='Random seed')
	p.add_argument('--log-file', type=str, default='exfiltration_simulation.log', help='File to write detailed logs')
	p.add_argument('--log-level', type=str, default='INFO', help='Log level for file output (DEBUG, INFO, WARNING, ERROR)')
	return p.parse_args()


if __name__ == '__main__':
	args = parse_args()
	run_simulation(args)
