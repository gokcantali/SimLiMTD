# SimLiMTD

SimLiMTD is a modular simulation and analysis toolkit for studying moving target defense (MTD) strategies in containerized microservice environments.

It covers two security scenarios:

- Malware infection and propagation across connected containers
- Data exfiltration by a malicious tenant co-located with victim containers

The repository lets you run single simulations, Monte Carlo sweeps, and post-processing analysis for each scenario. The simulators are built on SimPy discrete-event modeling and generate JSON outputs with metrics such as migration counts, time budget usage, infection or exfiltration progress, and per-container or per-component outcomes. The Monte Carlo runners aggregate those outputs into CSV and JSON summaries that can be plotted or inspected in the dashboard.

## Project Structure

The repository has been reorganized into scenario-specific modules:

- [scenarios/malware/run_single_simulation.py](scenarios/malware/run_single_simulation.py) runs one malware-defense simulation
- [scenarios/malware/run_monte_carlo.py](scenarios/malware/run_monte_carlo.py) sweeps malware configurations and aggregates results
- [scenarios/malware/analyze_results.py](scenarios/malware/analyze_results.py) turns malware Monte Carlo summaries into plots
- [scenarios/exfiltration/run_single_simulation.py](scenarios/exfiltration/run_single_simulation.py) runs one exfiltration-defense simulation
- [scenarios/exfiltration/run_monte_carlo.py](scenarios/exfiltration/run_monte_carlo.py) sweeps exfiltration configurations and aggregates results
- [scenarios/exfiltration/analyze_results.py](scenarios/exfiltration/analyze_results.py) turns exfiltration Monte Carlo summaries into plots
- [dashboard.py](dashboard.py) launches the Streamlit-based GUI

Supporting folders:

- [microservice-configs/](microservice-configs) stores the default application configuration and any uploaded configs
- [results/](results) stores generated outputs, summaries, plots, and logs (not version controlled)

## Requirements

You need:

- Python 3.10 or newer
- `pip`
- A virtual environment is recommended

Optional but useful:

- `seaborn` for improved plot styling in the analysis scripts
- `poppler` on macOS if you want the dashboard to render generated PDF plots

## Installation

From a fresh checkout, install the Python dependencies with:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Afterwards, create the results folder to store the plots and logs of the executed simulations:

```bash
mkdir -p results
```

If you want the optional plotting enhancement for the analysis scripts, install seaborn too:

```bash
pip install seaborn
```

On macOS, if the dashboard cannot render generated PDF plots, install Poppler first:

```bash
brew install poppler
```

## Running Simulations

All commands below assume you are in the repository root.

### Single malware simulation

Run one malware-defense simulation with a specific runtime, time budget, and policy choice:

```bash
python scenarios/malware/run_single_simulation.py \
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
python scenarios/exfiltration/run_single_simulation.py \
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
python scenarios/malware/run_monte_carlo.py \
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
python scenarios/exfiltration/run_monte_carlo.py \
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
python scenarios/malware/analyze_results.py "$(ls -t results/malware/monte_carlo_*/monte_carlo_summary_*.csv | head -n 1)"
python scenarios/exfiltration/analyze_results.py "$(ls -t results/exfiltration/monte_carlo_*/monte_carlo_summary_*.csv | head -n 1)"
```

Each analysis script prints a textual summary to the console and saves PDF plots into the `analysis/` subdirectory beside the CSV file.

### Use the dashboard

Launch the Streamlit interface if you want a browser-based workflow for running simulations and reviewing outputs:

```bash
streamlit run dashboard.py
```

From the dashboard you can:

- Choose the scenario: malware or exfiltration
- Run a single configuration or a Monte Carlo sweep
- Upload or select a microservice configuration file
- Inspect summaries, tables, logs, and generated plots in one place

## Output Interpretation

The main metrics differ by scenario, but the overall goal is the same: lower attack success, slower propagation, more effective migrations, and better use of the migration time budget.

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

- The default microservice configuration is stored in [microservice-configs/default.json](microservice-configs/default.json)
- Most scripts assume they are launched from the repository root
- If you run large Monte Carlo sweeps, the scripts will ask for confirmation unless `--auto-confirm` is supplied

## Example Workflow

1. Install dependencies.
2. Run a single simulation to validate your setup.
3. Launch a Monte Carlo sweep for the scenario you care about.
4. Generate plots from the resulting summary CSV.
5. Use the dashboard if you want to compare results interactively.

## License

This project is distributed under the terms of the [LICENSE](LICENSE) file.
