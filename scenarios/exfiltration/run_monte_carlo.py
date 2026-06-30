#!/usr/bin/env python3
"""
Monte Carlo Simulation for Exfiltration Defense Analysis

Runs run_monte_carlo.py with various configurations across multiple seeds
and aggregates results to analyze the effectiveness of different MTD strategies.

Usage:
    python scenarios/exfiltration/run_monte_carlo.py [--runs-per-config N] [--parallel]
"""

import argparse
import csv
import json
import multiprocessing
import os
import statistics
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List


def run_simulation_wrapper(config: dict) -> tuple:
    """
    Wrapper function for parallel execution.
    Takes a config dict and returns (config_key, metrics).
    """
    output_dir = config['output_dir']
    result = run_simulation(config, output_dir)
    metrics = extract_metrics(result)
    
    # Return tuple of (config_key, seed, metrics) for easier aggregation
    config_key = (
        config['time_budget'],
        config['runtime'],
        config['num_nodes'],
        config['num_tenants'],
        config['migration_rollback'],
        config['migration_method_policy']
    )
    return (config_key, config['seed'], metrics)


def run_simulation(config: dict, output_dir: Path) -> Dict:
    """
    Run a single exfiltration simulation and return the results.
    
    Args:
        config: Dictionary with simulation parameters
        output_dir: Directory to save results
    
    Returns:
        Dict with simulation results, or None if simulation failed
    """
    # Create output filename
    config_str = f"tb{config['time_budget']}_rt{config['runtime']}_nodes{config['num_nodes']}_tenants{config['num_tenants']}_rollback{config['migration_rollback']:.1f}_{config['migration_method_policy']}_s{config['seed']}"
    output_file = output_dir / f"logs/{config_str}.json"
    log_file = output_dir / f"logs/{config_str}.log"
    
    # Build command
    cmd = [
        "python", "scenarios/exfiltration/run_single_simulation.py",
        "--runtime", str(config['runtime']),
        "--time-budget", str(config['time_budget']),
        "--num-nodes", str(config['num_nodes']),
        "--num-tenants", str(config['num_tenants']),
        "--migration-rollback", str(config['migration_rollback']),
        "--migration-method-policy", config['migration_method_policy'],
        "--migration-policy", "random",  # Use priority_based for consistency
        "--malicious-tenant-id", "0",  # Keep first tenant as malicious
        "--config-file", config.get('config_file', 'microservice-config.json'),
        "--output", str(output_file),
        "--log-file", str(log_file),
        "--log-level", "WARNING",  # Reduce log verbosity for batch runs
        "--seed", str(config['seed']),
    ]
    
    # Add migration period parameters
    if config.get('auto_migration_period', True):
        cmd.append("--auto-migration-period")
    else:
        cmd.extend(["--manual-migration-period", "--migration-period", str(config.get('migration_period', 300.0))])
    
    try:
        # Run simulation
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # 10 minute timeout per simulation
        )
        
        if result.returncode != 0:
            print(f"  ERROR: Simulation failed with return code {result.returncode}", file=sys.stderr)
            print(f"  STDERR: {result.stderr[:500]}", file=sys.stderr)
            return None
        
        # Load results
        with open(output_file, 'r') as f:
            data = json.load(f)
        
        return data
    
    except subprocess.TimeoutExpired:
        print(f"  TIMEOUT: Simulation exceeded 10 minutes", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  ERROR: {e}", file=sys.stderr)
        return None


def extract_metrics(result: Dict) -> Dict:
    """Extract key metrics from simulation result."""
    if result is None:
        return None
    
    metrics = {
        # Core metrics requested
        'total_exfiltration': result.get('total_exfiltrated', 0.0),
        'weighted_exfiltration': result.get('weighted_exfiltration', 0.0),
        'time_budget_remaining': result.get('time_budget_remaining', 0.0),
        
        # Additional useful metrics
        'migrations': result.get('migrations', 0),
        'total_migration_time': result.get('total_migration_time', 0.0),
        'num_containers': result.get('num_containers', 0),
        'completion_times': result.get('container_completion_times', []),
        'num_completed': len(result.get('container_completion_times', [])),
        'avg_exfiltration_rate': result.get('avg_exfiltration_rate', 0.0),
    }
    
    return metrics


def aggregate_metrics(metrics_list: List[Dict]) -> Dict:
    """
    Aggregate metrics across multiple runs.
    
    Returns dict with mean and std for each metric.
    """
    if not metrics_list:
        return {}
    
    # Filter out None values
    valid_metrics = [m for m in metrics_list if m is not None]
    
    if not valid_metrics:
        return {}
    
    aggregated = {
        'num_runs': len(valid_metrics),
        'num_failed': len(metrics_list) - len(valid_metrics),
    }
    
    # For each metric, compute mean and std
    metric_keys = [
        'total_exfiltration',
        'weighted_exfiltration',
        'time_budget_remaining',
        'migrations',
        'total_migration_time',
        'num_completed',
        'avg_exfiltration_rate',
    ]
    
    for key in metric_keys:
        values = [m[key] for m in valid_metrics if m.get(key) is not None]
        
        if values:
            import statistics
            aggregated[f'{key}_mean'] = statistics.mean(values)
            aggregated[f'{key}_std'] = statistics.stdev(values) if len(values) > 1 else 0.0
        else:
            aggregated[f'{key}_mean'] = None
            aggregated[f'{key}_std'] = None
    
    return aggregated


def run_monte_carlo(configs: List[dict], output_dir: Path, num_workers: int = 1) -> Dict:
    """
    Run Monte Carlo simulation across all configurations.
    
    Args:
        configs: List of configuration dictionaries
        output_dir: Directory to save results
        num_workers: Number of parallel workers. 1 = sequential, >1 = parallel.
    
    Returns:
        Dict mapping config tuple -> aggregated metrics
    """
    results = {}
    
    # Group configs by parameter set (excluding seed)
    # Include migration_period in key if manual mode
    config_groups = defaultdict(list)
    for config in configs:
        if config.get('auto_migration_period', True):
            key = (
                config['time_budget'],
                config['runtime'],
                config['num_nodes'],
                config['num_tenants'],
                config['migration_rollback'],
                config['migration_method_policy']
            )
        else:
            key = (
                config['time_budget'],
                config['runtime'],
                config['num_nodes'],
                config['num_tenants'],
                config['migration_rollback'],
                config['migration_method_policy'],
                config['migration_period']
            )
        config_groups[key].append(config)
    
    total_configs = len(config_groups)
    total_sims = len(configs)
    print(f"Running Monte Carlo simulation with {total_configs} unique configurations")
    print(f"Total simulations: {total_sims}")
    print(f"Using {num_workers} worker(s) for parallel execution")
    print(f"Results will be saved to: {output_dir}")
    print()
    
    # Run simulations in parallel or sequential
    if num_workers > 1:
        # Parallel execution
        print(f"Starting parallel execution with {num_workers} workers...")
        with multiprocessing.Pool(processes=num_workers) as pool:
            # Use imap_unordered to get results as they complete
            sim_results = []
            for i, result in enumerate(pool.imap_unordered(run_simulation_wrapper, configs), 1):
                sim_results.append(result)
                config_key, seed, metrics = result
                tb, rt, nodes, tenants, rollback, policy = config_key
                
                # Print progress
                if metrics and metrics.get('weighted_exfiltration') is not None:
                    print(f"[{i}/{total_sims}] TB={tb}, RT={rt}, Nodes={nodes}, Tenants={tenants}, Rollback={rollback:.1f}, Policy={policy}, Seed={seed}: ✓ (Weighted Exfil: {metrics['weighted_exfiltration']:.1f})")
                else:
                    print(f"[{i}/{total_sims}] TB={tb}, RT={rt}, Nodes={nodes}, Tenants={tenants}, Rollback={rollback:.1f}, Policy={policy}, Seed={seed}: ✗ (failed)")
    else:
        # Sequential execution (original behavior)
        sim_results = []
        for i, config in enumerate(configs, 1):
            print(f"[{i}/{total_sims}] TB={config['time_budget']}, RT={config['runtime']}, Nodes={config['num_nodes']}, Tenants={config['num_tenants']}, Rollback={config['migration_rollback']:.1f}, Policy={config['migration_method_policy']}, Seed={config['seed']}...", end=' ', flush=True)
            result = run_simulation_wrapper(config)
            sim_results.append(result)
            
            config_key, seed, metrics = result
            if metrics and metrics.get('weighted_exfiltration') is not None:
                print(f"✓ (Weighted Exfil: {metrics['weighted_exfiltration']:.1f})")
            else:
                print("✗ (failed)")
    
    # Group results by configuration and aggregate
    config_metrics = defaultdict(list)
    for config_key, seed, metrics in sim_results:
        config_metrics[config_key].append(metrics)
    
    # Aggregate metrics for each configuration
    print("\nAggregating results...")
    for config_num, (key, metrics_list) in enumerate(sorted(config_metrics.items()), 1):
        if len(key) == 7:  # Manual migration period mode
            tb, rt, nodes, tenants, rollback, policy, mp = key
            print(f"[{config_num}/{total_configs}] Configuration: TB={tb}, RT={rt}, Nodes={nodes}, Tenants={tenants}, Rollback={rollback:.1f}, Policy={policy}, MP={mp}")
        else:  # Auto migration period mode
            tb, rt, nodes, tenants, rollback, policy = key
            print(f"[{config_num}/{total_configs}] Configuration: TB={tb}, RT={rt}, Nodes={nodes}, Tenants={tenants}, Rollback={rollback:.1f}, Policy={policy}")
        # Aggregate metrics across seeds
        aggregated = aggregate_metrics(metrics_list)
        results[key] = aggregated
        
        if aggregated.get('weighted_exfiltration_mean') is not None:
            print(f"  Summary: Weighted Exfil: {aggregated['weighted_exfiltration_mean']:.1f} ± {aggregated['weighted_exfiltration_std']:.1f}")
        else:
            print(f"  Summary: Failed")
        print()
    
    return results


def save_summary_csv(results: Dict, output_file: Path):
    """Save aggregated results to CSV file."""
    
    if not results:
        print("No results to save.")
        return
    
    # Prepare rows
    rows = []
    for (tb, rt, nodes, tenants, rollback, policy), metrics in sorted(results.items()):
        row = {
            'time_budget': tb,
            'runtime': rt,
            'num_nodes': nodes,
            'num_tenants': tenants,
            'migration_rollback': rollback,
            'migration_method_policy': policy,
            'num_runs': metrics.get('num_runs', 0),
            'num_failed': metrics.get('num_failed', 0),
            'total_exfiltration_mean': metrics.get('total_exfiltration_mean'),
            'total_exfiltration_std': metrics.get('total_exfiltration_std'),
            'weighted_exfiltration_mean': metrics.get('weighted_exfiltration_mean'),
            'weighted_exfiltration_std': metrics.get('weighted_exfiltration_std'),
            'time_budget_remaining_mean': metrics.get('time_budget_remaining_mean'),
            'time_budget_remaining_std': metrics.get('time_budget_remaining_std'),
            'migrations_mean': metrics.get('migrations_mean'),
            'migrations_std': metrics.get('migrations_std'),
            'total_migration_time_mean': metrics.get('total_migration_time_mean'),
            'total_migration_time_std': metrics.get('total_migration_time_std'),
            'num_completed_mean': metrics.get('num_completed_mean'),
            'num_completed_std': metrics.get('num_completed_std'),
            'avg_exfiltration_rate_mean': metrics.get('avg_exfiltration_rate_mean'),
            'avg_exfiltration_rate_std': metrics.get('avg_exfiltration_rate_std'),
        }
        rows.append(row)
    
    # Write CSV
    if rows:
        import csv
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        
        print(f"Summary CSV saved to: {output_file}")


def save_summary_json(results: Dict, output_file: Path):
    """Save aggregated results to JSON file."""
    
    # Convert tuple keys to strings for JSON serialization
    json_results = {
        f"tb{tb}_rt{rt}_nodes{nodes}_tenants{tenants}_rollback{rollback:.1f}_{policy}": metrics
        for (tb, rt, nodes, tenants, rollback, policy), metrics in results.items()
    }
    
    output_data = {
        'timestamp': datetime.now().isoformat(),
        'results': json_results,
    }
    
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"Summary JSON saved to: {output_file}")


def print_top_configurations(results: Dict, n: int = 10):
    """Print top N configurations ranked by lowest weighted exfiltration."""
    
    print(f"\n{'='*80}")
    print(f"TOP {n} CONFIGURATIONS (by lowest weighted exfiltration)")
    print(f"{'='*80}\n")
    
    # Filter configurations with valid results
    valid_configs = [
        (key, metrics)
        for key, metrics in results.items()
        if metrics.get('weighted_exfiltration_mean') is not None
    ]
    
    if not valid_configs:
        print("No valid configurations found.")
        return
    
    # Sort by weighted exfiltration (lower is better for defense)
    sorted_configs = sorted(
        valid_configs,
        key=lambda x: x[1]['weighted_exfiltration_mean'],
        reverse=False  # Lower exfiltration is better
    )
    
    for i, ((tb, rt, nodes, tenants, rollback, policy), metrics) in enumerate(sorted_configs[:n], 1):
        print(f"{i}. TB={tb}s, RT={rt}s, Nodes={nodes}, Tenants={tenants}, Rollback={rollback:.1f}, Policy={policy}")
        print(f"   Weighted Exfil: {metrics['weighted_exfiltration_mean']:.1f} ± {metrics['weighted_exfiltration_std']:.1f}")
        print(f"   Total Exfil: {metrics['total_exfiltration_mean']:.1f} ± {metrics['total_exfiltration_std']:.1f}")
        print(f"   Migrations: {metrics['migrations_mean']:.1f}, Completed: {metrics['num_completed_mean']:.1f}")
        print()


def main():
    parser = argparse.ArgumentParser(description='Monte Carlo simulation for exfiltration defense')
    parser.add_argument('--time-budget-range', nargs=3, type=float, 
                       default=[100, 2000, 100],
                       metavar=('START', 'STOP', 'STEP'),
                       help='Time budget range: start stop step (default: 100 2000 100)')
    parser.add_argument('--runtime-range', nargs=3, type=float,
                       default=[1000, 10000, 500],
                       metavar=('START', 'STOP', 'STEP'),
                       help='Runtime range: start stop step (default: 1000 10000 500)')
    parser.add_argument('--nodes-range', nargs=3, type=int,
                       default=[2, 5, 1],
                       metavar=('START', 'STOP', 'STEP'),
                       help='Number of nodes range: start stop step (default: 2 5 1)')
    parser.add_argument('--tenants-range', nargs=3, type=int,
                       default=[1, 10, 1],
                       metavar=('START', 'STOP', 'STEP'),
                       help='Number of tenants range: start stop step (default: 1 10 1)')
    parser.add_argument('--rollback-range', nargs=3, type=float,
                       default=[0.1, 0.5, 0.1],
                       metavar=('START', 'STOP', 'STEP'),
                       help='Migration rollback range: start stop step (default: 0.1 0.5 0.1)')
    parser.add_argument('--seed-range', nargs=3, type=int,
                       default=[0, 1000, 50],
                       metavar=('START', 'STOP', 'STEP'),
                       help='Seed range: start stop step (default: 1 1000 50)')
    parser.add_argument('--output-dir', type=str, default='results/exfiltration',
                       help='Output directory for results (default: results/exfiltration)')
    parser.add_argument('--top-n', type=int, default=10,
                       help='Number of top configurations to display (default: 10)')
    parser.add_argument('--quick-test', action='store_true',
                       help='Run quick test with reduced parameter ranges')
    parser.add_argument('--auto-confirm', action='store_true', help='Automatically confirm running the simulation without user prompt')
    parser.add_argument('--config-file', type=str, default='./microservice-configs/default.json',
                       help='Path to microservice configuration file (default: microservice-config.json)')
    parser.add_argument('--workers', type=int, default=None,
                       help='Number of parallel workers (default: auto-detect CPU count, use 1 for sequential)')
    parser.add_argument('--auto-migration-period', action='store_true', default=True,
                       help='Automatically calculate migration period based on runtime and time budget (default: True)')
    parser.add_argument('--manual-migration-period', dest='auto_migration_period', action='store_false',
                       help='Use manual migration period instead of auto-calculation')
    parser.add_argument('--migration-period-range', nargs=3, type=float,
                       default=[100, 500, 50],
                       metavar=('START', 'STOP', 'STEP'),
                       help='Migration period range when using manual mode: start stop step (default: 100 500 50)')
    
    args = parser.parse_args()
    
    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / 'logs').mkdir(exist_ok=True)
    
    # Generate ranges
    if args.quick_test:
        # Quick test with smaller ranges
        time_budgets = [100, 500, 1000]
        runtimes = [1000, 3000, 5000]
        nodes_range = [4, 6, 8]
        tenants_range = [2, 3]
        rollback_range = [0.1, 0.3]
        seeds = [1, 51]
    else:
        time_budgets = []
        tb_start, tb_stop, tb_step = args.time_budget_range
        tb_val = tb_start
        while tb_val <= tb_stop:
            time_budgets.append(int(tb_val))
            tb_val += tb_step
        
        runtimes = []
        rt_start, rt_stop, rt_step = args.runtime_range
        rt_val = rt_start
        while rt_val <= rt_stop:
            runtimes.append(int(rt_val))
            rt_val += rt_step
        
        nodes_range = list(range(args.nodes_range[0], args.nodes_range[1] + 1, args.nodes_range[2]))
        tenants_range = list(range(args.tenants_range[0], args.tenants_range[1] + 1, args.tenants_range[2]))
        
        rollback_range = []
        rb_val = args.rollback_range[0]
        while rb_val <= args.rollback_range[1] + 0.01:  # Add small epsilon for float comparison
            rollback_range.append(round(rb_val, 1))
            rb_val += args.rollback_range[2]
        
        seeds = list(range(args.seed_range[0], args.seed_range[1] + 1, args.seed_range[2]))
    
    migration_policies = ['always_precopy', 'min_time', 'no_mtd']
    
    # Generate migration period range (only used if manual mode)
    if args.auto_migration_period:
        migration_periods = [300.0]  # Single value, auto mode will ignore it
    else:
        migration_periods = []
        mp_val = args.migration_period_range[0]
        while mp_val <= args.migration_period_range[1] + 0.01:  # Add small epsilon for float comparison
            migration_periods.append(round(mp_val, 1))
            mp_val += args.migration_period_range[2]
    
    # Generate all configurations
    configs = []
    for tb in time_budgets:
        for rt in runtimes:
            for nodes in nodes_range:
                for tenants in tenants_range:
                    for rollback in rollback_range:
                        for policy in migration_policies:
                            for mp in migration_periods:
                                for seed in seeds:
                                    configs.append({
                                        'time_budget': tb,
                                        'runtime': rt,
                                        'num_nodes': nodes,
                                        'num_tenants': tenants,
                                        'migration_rollback': rollback,
                                        'migration_method_policy': policy,
                                        'seed': seed,
                                        'config_file': args.config_file,
                                        'output_dir': output_dir,
                                        'auto_migration_period': args.auto_migration_period,
                                        'migration_period': mp,
                                    })
    
    # Determine number of workers
    if args.workers is None:
        num_workers = max(1, multiprocessing.cpu_count() - 1)  # Leave one core free
    else:
        num_workers = max(1, args.workers)
    
    print(f"Monte Carlo Simulation Configuration:")
    print(f"  Time budgets: {len(time_budgets)} values from {min(time_budgets)} to {max(time_budgets)}")
    print(f"  Runtimes: {len(runtimes)} values from {min(runtimes)} to {max(runtimes)}")
    print(f"  Node counts: {len(nodes_range)} values: {nodes_range}")
    print(f"  Tenant counts: {len(tenants_range)} values: {tenants_range}")
    print(f"  Rollback percentages: {len(rollback_range)} values: {rollback_range}")
    print(f"  Seeds: {len(seeds)} values from {min(seeds)} to {max(seeds)}")
    print(f"  Migration policies: {migration_policies}")
    
    if args.auto_migration_period:
        unique_configs = len(time_budgets) * len(runtimes) * len(nodes_range) * len(tenants_range) * len(rollback_range) * len(migration_policies)
        print(f"  Migration period mode: Auto (calculated per config)")
    else:
        unique_configs = len(time_budgets) * len(runtimes) * len(nodes_range) * len(tenants_range) * len(rollback_range) * len(migration_policies) * len(migration_periods)
        print(f"  Migration periods: {len(migration_periods)} values from {min(migration_periods)} to {max(migration_periods)}")
        print(f"  Migration period mode: Manual (testing {len(migration_periods)} different periods)")
    
    print(f"  Unique configurations: {unique_configs}")
    print(f"  Total simulations: {len(configs)}")
    print(f"  Parallel workers: {num_workers} (CPU cores available: {multiprocessing.cpu_count()})")
    print()
    
    # Confirm with user if running many simulations
    if len(configs) > 100 and not args.quick_test:
        if not args.auto_confirm:
            response = input(f"About to run {len(configs)} simulations. Continue? (y/N): ")
            if response.lower() != 'y':
                print("Aborted.")
                return
    
    # Run Monte Carlo simulation
    start_time = datetime.now()
    results = run_monte_carlo(configs, output_dir, num_workers=num_workers)
    end_time = datetime.now()
    
    # Save summary results
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    csv_file = output_dir / f'monte_carlo_summary_{timestamp}.csv'
    json_file = output_dir / f'monte_carlo_summary_{timestamp}.json'
    
    save_summary_csv(results, csv_file)
    save_summary_json(results, json_file)
    
    # Print top configurations
    print_top_configurations(results, n=args.top_n)
    
    # Print execution time
    duration = end_time - start_time
    print(f"\n{'='*80}")
    print(f"Monte Carlo simulation completed in {duration}")
    print(f"Total simulations run: {sum(m.get('num_runs', 0) for m in results.values())}")
    print(f"Results saved to: {output_dir}")
    print(f"{'='*80}\n")


if __name__ == '__main__':
    main()
