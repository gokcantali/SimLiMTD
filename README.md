# SimLiMTD

SimLiMTD is a simulation and analysis toolkit for studying moving target defense (MTD) strategies in containerized microservice environments.

It models two security scenarios:

- Malware infection and propagation across connected containers
- Data exfiltration by a malicious tenant that co-locates with victim containers

The repository provides both single-run simulators and Monte Carlo drivers so you can compare migration policies, migration methods, runtime budgets, and infrastructure sizes across many configurations. Results are written to JSON and CSV files, and the analysis scripts generate publication-style plots from those summaries.

## What This Repository Offers

The codebase is organized around four main entry points:

- [malware_simulation.py](malware_simulation.py) runs one malware-defense simulation
- [exfiltration_simulation.py](exfiltration_simulation.py) runs one exfiltration-defense simulation
- [malware_monte_carlo.py](malware_monte_carlo.py) sweeps many malware configurations and aggregates results
- [exfiltration_monte_carlo.py](exfiltration_monte_carlo.py) sweeps many exfiltration configurations and aggregates results

Two analysis helpers turn summary CSV files into plots:

- [analyze_malware_results.py](analyze_malware_results.py)
- [analyze_exfiltration_results.py](analyze_exfiltration_results.py)

There is also a Streamlit GUI for users who prefer a visual workflow:

- [simulation_gui.py](simulation_gui.py)

The simulators use SimPy discrete-event modeling, and each run produces metrics such as migration counts, time budget usage, infection or exfiltration progress, and per-container or per-component outcomes. The Monte Carlo scripts then aggregate those per-run metrics into summary tables and plots so you can compare policies under the same workload.

## Repository Layout

- `microservice-configs/` contains the default microservice application configuration used by the simulations
- `results/` stores generated outputs, summaries, plots, and logs
- `data/` is available for any supporting datasets or experiment inputs

## Requirements

You need:

- Python 3.10 or newer
- `pip`
- A virtual environment is recommended

Optional but useful:

- `seaborn` for improved plot styling in the analysis scripts
- `poppler` if you use the GUI on macOS to convert PDF plots into displayable images

## Installation

From a fresh checkout, install the Python dependencies with:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If you want the optional plotting enhancement for the analysis scripts, install seaborn too:

```bash
pip install seaborn
```

On macOS, if the GUI cannot render generated PDF plots, install Poppler first:

```bash
brew install poppler
```

## Running Simulations

All commands below assume you are in the repository root.

### Single malware simulation

Run one malware-defense simulation with a specific runtime, time budget, and policy choice:

```bash
python malware_simulation.py \
	--runtime 3600 \
	--time-budget 1000 \
	--num-nodes 8 \
	--migration-policy random \
	--migration-method-policy always_precopy \
	--config-file microservice-configs/default.json \
	--output results/malware/single_run/results.json \
	--log-file results/malware/single_run/simulation.log
```

Useful flags:

- `--migration-policy` chooses which container is migrated next: `random`, `infected_first`, or `priority_based`
- `--migration-method-policy` chooses the migration method for stateful containers: `always_precopy`, `always_cold`, or `min_time`
- `--auto-migration-period` or `--manual-migration-period` controls whether migration timing is derived automatically from the workload or set manually with `--migration-period`

### Single exfiltration simulation

Run one exfiltration-defense simulation:

```bash
python exfiltration_simulation.py \
	--runtime 3600 \
	--time-budget 1000 \
	--num-nodes 4 \
	--num-tenants 5 \
	--malicious-tenant-id 0 \
	--migration-rollback 0.1 \
	--migration-policy random \
	--migration-method-policy always_precopy \
	--config-file microservice-configs/default.json \
	--output results/exfiltration/single_run/results.json \
	--log-file results/exfiltration/single_run/simulation.log
```

Useful flags:

- `--num-tenants` sets how many tenants are simulated
- `--malicious-tenant-id` selects which tenant is attacker-controlled
- `--migration-rollback` controls how much exfiltration progress is lost during migration

### Malware Monte Carlo sweep

Run a parameter sweep over time budget, runtime, and seed values:

```bash
python malware_monte_carlo.py \
	--time-budget-range 100 2000 100 \
	--runtime-range 1000 10000 500 \
	--seed-range 1 10 1 \
	--config-file microservice-configs/default.json \
	--output-dir results/malware \
	--auto-confirm
```

If you want to vary migration period manually instead of using automatic calculation, add `--manual-migration-period` and set `--migration-period-range`.

### Exfiltration Monte Carlo sweep

Run a sweep over time budget, runtime, node count, tenant count, rollback percentage, and seed values:

```bash
python exfiltration_monte_carlo.py \
	--time-budget-range 100 2000 100 \
	--runtime-range 1000 10000 500 \
	--nodes-range 2 5 1 \
	--tenants-range 1 10 1 \
	--rollback-range 0.1 0.5 0.1 \
	--seed-range 0 1000 50 \
	--config-file microservice-configs/default.json \
	--output-dir results/exfiltration \
	--auto-confirm
```

For quicker exploratory runs, add `--quick-test` to reduce the search space.

## Viewing Results

Every simulation writes its output to a scenario-specific folder under `results/`.

Typical output includes:

- `results.json` for single-run simulations
- `monte_carlo_summary_*.csv` and `monte_carlo_summary_*.json` for Monte Carlo runs
- `logs/` for detailed per-run execution logs
- `analysis/` for generated plots created by the analysis scripts

### Generate plots from summary CSV files

After a Monte Carlo run, point the corresponding analysis script at one generated summary CSV from the most recent run folder:

```bash
python analyze_malware_results.py "$(ls -t results/malware/monte_carlo_*/monte_carlo_summary_*.csv | head -n 1)"
python analyze_exfiltration_results.py "$(ls -t results/exfiltration/monte_carlo_*/monte_carlo_summary_*.csv | head -n 1)"
```

Each analysis script prints a textual summary to the console and saves PDF plots into the `analysis/` subdirectory beside the CSV file.

### Use the GUI

Launch the Streamlit interface if you want a browser-based workflow for running simulations and reviewing outputs:

```bash
streamlit run simulation_gui.py
```

From the GUI you can:

- Choose the scenario: malware or exfiltration
- Run a single configuration or a Monte Carlo sweep
- Upload or select a microservice configuration file
- Inspect summaries, tables, logs, and generated plots in one place

## Output Interpretation

The main metrics differ by scenario, but the overall goal is the same: lower attack success, slower propagation, more migrations used effectively, and better use of the migration time budget.

For malware runs, look at:

- `all_types_infected_time`: how long it took the attacker to infect every component type
- `all_types_infected_rate`: how often the attacker succeeded
- `migrations`, `infections_cleaned`, and `time_budget_remaining`

For exfiltration runs, look at:

- `weighted_exfiltration_mean`: priority-weighted stolen data, where lower is better
- `total_exfiltration_mean`: total exfiltrated data
- `num_completed_mean`: how many containers were fully exfiltrated
- `migrations_mean` and `time_budget_remaining_mean`

## Notes

- The default microservice configuration is stored in `microservice-configs/default.json`
- Most scripts assume they are launched from the repository root
- If you run large Monte Carlo sweeps, the scripts will ask for confirmation unless `--auto-confirm` is supplied

## Example Workflow

1. Install dependencies.
2. Run a single simulation to validate your setup.
3. Launch a Monte Carlo sweep for the scenario you care about.
4. Generate plots from the resulting summary CSV.
5. Use the GUI if you want to compare results interactively.

## License

This project is distributed under the terms of the [LICENSE](LICENSE) file.
