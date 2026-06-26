#!/usr/bin/env python3
"""
Monte Carlo Simulation GUI Application

A comprehensive Streamlit-based GUI for running malware and exfiltration simulations
in both single-config and multiple-config modes.

Usage:
    streamlit run dashboard.py
"""

import streamlit as st
import subprocess
import json
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path
from datetime import datetime
import time
import os
import sys
from PIL import Image
from pdf2image import convert_from_path
import shutil

# Page configuration
st.set_page_config(
    page_title="MTD Monte Carlo Simulation",
    page_icon="🔬",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Directory for storing uploaded config files
CONFIG_DIR = Path('microservice-configs')
CONFIG_DIR.mkdir(exist_ok=True)

# Custom CSS for better styling
st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        color: #1f77b4;
        text-align: center;
        padding: 1rem 0;
        border-bottom: 3px solid #1f77b4;
        margin-bottom: 2rem;
    }
    .stButton>button {
        width: 100%;
        background-color: #1f77b4;
        color: white;
        font-weight: 600;
        padding: 0.75rem;
        border-radius: 0.5rem;
    }
    .stButton>button:hover {
        background-color: #1558a5;
    }
    .success-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        color: #155724;
        margin: 1rem 0;
    }
    .error-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        color: #721c24;
        margin: 1rem 0;
    }
    .info-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #d1ecf1;
        border: 1px solid #bee5eb;
        color: #0c5460;
        margin: 1rem 0;
    }
    .metric-card {
        background-color: #f8f9fa;
        padding: 1rem;
        border-radius: 0.5rem;
        border: 1px solid #dee2e6;
        margin: 0.5rem 0;
    }
    </style>
""", unsafe_allow_html=True)


def get_available_configs():
    """Get list of available microservice configuration files."""
    configs = []
    
    # Add default config if it exists
    default_config = CONFIG_DIR / 'default.json'
    if default_config.exists():
        configs.append(str(default_config))
    
    # Add uploaded configs
    if CONFIG_DIR.exists():
        for config_file in sorted(CONFIG_DIR.glob('*.json')):
            configs.append(str(config_file))
    
    return configs


def validate_config_file(file_path):
    """Validate that a config file has the correct structure."""
    try:
        with open(file_path, 'r') as f:
            config = json.load(f)
        
        # Check for required structure
        if 'applications' not in config:
            return False, "Missing 'applications' key"
        
        if not isinstance(config['applications'], dict):
            return False, "'applications' must be a dictionary"
        
        if len(config['applications']) == 0:
            return False, "No applications defined"
        
        # Check that at least one application has components
        for app_name, app_config in config['applications'].items():
            if 'components' not in app_config:
                return False, f"Application '{app_name}' missing 'components' key"
            if not isinstance(app_config['components'], dict):
                return False, f"Components in '{app_name}' must be a dictionary"
        
        return True, "Valid configuration"
    
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON: {str(e)}"
    except Exception as e:
        return False, f"Error reading file: {str(e)}"


def save_uploaded_config(uploaded_file):
    """Save an uploaded config file and return the path."""
    try:
        # Generate filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        original_name = Path(uploaded_file.name).stem
        new_filename = f"{original_name}_{timestamp}.json"
        file_path = CONFIG_DIR / new_filename
        
        # Save file
        with open(file_path, 'wb') as f:
            f.write(uploaded_file.getbuffer())
        
        # Validate
        is_valid, message = validate_config_file(file_path)
        
        if not is_valid:
            # Remove invalid file
            file_path.unlink()
            return None, f"Invalid config file: {message}"
        
        return str(file_path), "Config file uploaded successfully"
    
    except Exception as e:
        return None, f"Error saving file: {str(e)}"


def get_default_params(scenario, mode):
    """Get default parameters for a given scenario and mode."""
    defaults = {
        'malware': {
            'single': {
                'runtime': 3600,
                'time_budget': 500,
                'num_nodes': 8,
                'migration_policy': 'random',
                'migration_method_policy': 'always_precopy',
                'auto_migration_period': True,
                'migration_period': 300.0,
                'seed': 42,
            },
            'multiple': {
                'time_budget_start': 100,
                'time_budget_stop': 2000,
                'time_budget_step': 100,
                'runtime_start': 1000,
                'runtime_stop': 10000,
                'runtime_step': 500,
                'seed_start': 1,
                'seed_stop': 10,
                'seed_step': 1,
                'auto_migration_period': True,
                'migration_period_start': 100.0,
                'migration_period_stop': 500.0,
                'migration_period_step': 50.0,
            }
        },
        'exfiltration': {
            'single': {
                'runtime': 3600,
                'time_budget': 500,
                'num_nodes': 4,
                'num_tenants': 5,
                'malicious_tenant_id': 0,
                'migration_rollback': 0.1,
                'migration_policy': 'random',
                'migration_method_policy': 'always_precopy',
                'auto_migration_period': True,
                'migration_period': 300.0,
                'seed': 42,
            },
            'multiple': {
                'time_budget_start': 100,
                'time_budget_stop': 2000,
                'time_budget_step': 100,
                'runtime_start': 1000,
                'runtime_stop': 10000,
                'runtime_step': 500,
                'nodes_start': 2,
                'nodes_stop': 5,
                'nodes_step': 1,
                'tenants_start': 2,
                'tenants_stop': 10,
                'tenants_step': 1,
                'rollback_start': 0.1,
                'rollback_stop': 0.5,
                'rollback_step': 0.1,
                'seed_start': 0,
                'seed_stop': 1000,
                'seed_step': 50,
                'auto_migration_period': True,
                'migration_period_start': 100.0,
                'migration_period_stop': 500.0,
                'migration_period_step': 50.0,
            }
        }
    }
    return defaults.get(scenario, {}).get(mode, {})


def run_single_config(scenario, params, config_file):
    """Run a single configuration simulation."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = Path(f'results/{scenario}/single_run_{timestamp}')
    output_dir.mkdir(parents=True, exist_ok=True)
    
    output_file = output_dir / 'results.json'
    log_file = output_dir / 'simulation.log'
    
    if scenario == 'malware':
        cmd = [
            'python', 'scenarios/malware/run_single_simulation.py',
            '--runtime', str(params['runtime']),
            '--time-budget', str(params['time_budget']),
            '--num-nodes', str(params['num_nodes']),
            '--migration-policy', params['migration_policy'],
            '--migration-method-policy', params['migration_method_policy'],
            '--seed', str(params['seed']),
            '--config-file', config_file,
            '--output', str(output_file),
            '--log-file', str(log_file),
            '--log-level', 'INFO',
        ]
        
        # Add migration period parameters
        if params.get('auto_migration_period', True):
            cmd.append('--auto-migration-period')
        else:
            cmd.extend(['--manual-migration-period', '--migration-period', str(params.get('migration_period', 300.0))])
    else:  # exfiltration
        cmd = [
            'python', 'scenarios/exfiltration/run_single_simulation.py',
            '--runtime', str(params['runtime']),
            '--time-budget', str(params['time_budget']),
            '--num-nodes', str(params['num_nodes']),
            '--num-tenants', str(params['num_tenants']),
            '--malicious-tenant-id', str(params['malicious_tenant_id']),
            '--migration-rollback', str(params['migration_rollback']),
            '--migration-policy', params['migration_policy'],
            '--migration-method-policy', params['migration_method_policy'],
            '--seed', str(params['seed']),
            '--config-file', config_file,
            '--output', str(output_file),
            '--log-file', str(log_file),
            '--log-level', 'INFO',
        ]
        
        # Add migration period parameters
        if params.get('auto_migration_period', True):
            cmd.append('--auto-migration-period')
        else:
            cmd.extend(['--manual-migration-period', '--migration-period', str(params.get('migration_period', 300.0))])
    
    return cmd, output_file, log_file


def run_multiple_config(scenario, params, config_file):
    """Run multiple configuration Monte Carlo simulation."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = Path(f'results/{scenario}/monte_carlo_{timestamp}')
    
    if scenario == 'malware':
        cmd = [
            'python', 'scenarios/malware/run_monte_carlo.py',
            '--time-budget-range', 
            str(params['time_budget_start']),
            str(params['time_budget_stop']),
            str(params['time_budget_step']),
            '--runtime-range',
            str(params['runtime_start']),
            str(params['runtime_stop']),
            str(params['runtime_step']),
            '--seed-range',
            str(params['seed_start']),
            str(params['seed_stop']),
            str(params['seed_step']),
            '--config-file', config_file,
            '--output-dir', str(output_dir),
            '--auto-confirm', # Automatically confirm running the simulation
        ]
        
        # Add migration period parameters
        if params.get('auto_migration_period', True):
            cmd.append('--auto-migration-period')
        else:
            cmd.extend([
                '--manual-migration-period',
                '--migration-period-range',
                str(params.get('migration_period_start', 100.0)),
                str(params.get('migration_period_stop', 500.0)),
                str(params.get('migration_period_step', 50.0))
            ])
    else:  # exfiltration
        cmd = [
            'python', 'scenarios/exfiltration/run_monte_carlo.py',
            '--time-budget-range',
            str(params['time_budget_start']),
            str(params['time_budget_stop']),
            str(params['time_budget_step']),
            '--runtime-range',
            str(params['runtime_start']),
            str(params['runtime_stop']),
            str(params['runtime_step']),
            '--nodes-range',
            str(params['nodes_start']),
            str(params['nodes_stop']),
            str(params['nodes_step']),
            '--tenants-range',
            str(params['tenants_start']),
            str(params['tenants_stop']),
            str(params['tenants_step']),
            '--rollback-range',
            str(params['rollback_start']),
            str(params['rollback_stop']),
            str(params['rollback_step']),
            '--seed-range',
            str(params['seed_start']),
            str(params['seed_stop']),
            str(params['seed_step']),
            '--config-file', config_file,
            '--output-dir', str(output_dir),
            '--auto-confirm', # Automatically confirm running the simulation
        ]
        
        # Add migration period parameters
        if params.get('auto_migration_period', True):
            cmd.append('--auto-migration-period')
        else:
            cmd.extend([
                '--manual-migration-period',
                '--migration-period-range',
                str(params.get('migration_period_start', 100.0)),
                str(params.get('migration_period_stop', 500.0)),
                str(params.get('migration_period_step', 50.0))
            ])
    
    return cmd, output_dir


def display_single_results(scenario, result_file, log_file):
    """Display results from a single configuration run."""
    st.subheader("📊 Simulation Results")
    
    # Create tabs for different views
    tab1, tab2, tab3 = st.tabs(["Summary", "Detailed Metrics", "Logs"])
    
    with tab1:
        if result_file.exists():
            with open(result_file, 'r') as f:
                results = json.load(f)
            
            # Display key metrics
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Runtime", f"{results['runtime']}s")
                st.metric("Migrations", results['migrations'])
            
            with col2:
                st.metric("Total Migration Time", f"{results['total_migration_time']:.2f}s")
                st.metric("Time Budget Remaining", f"{results['time_budget_remaining']:.2f}s")
            
            if scenario == 'malware':
                with col3:
                    st.metric("Infected Containers", results['infected_containers'])
                    st.metric("All Types Infected", "Yes" if results['all_types_infected'] else "No")
                
                with col4:
                    st.metric("Infections Cleaned", results['infections_cleaned'])
                    if results['all_types_infected_time']:
                        st.metric("Time to Infect All Types", f"{results['all_types_infected_time']:.2f}s")
                
                # Component metrics
                st.subheader("Component Infection Times")
                comp_data = []
                for comp_name, comp_metrics in results.get('component_metrics', {}).items():
                    comp_data.append({
                        'Component': comp_name,
                        'First Infection (s)': comp_metrics.get('first_infection_time', 'N/A'),
                        'Infected Count': comp_metrics['infected_containers'],
                        'Total Count': comp_metrics['total_containers']
                    })
                if comp_data:
                    st.dataframe(pd.DataFrame(comp_data), use_container_width=True)
            
            else:  # exfiltration
                with col3:
                    st.metric("Total Exfiltration", f"{results['total_exfiltrated']:.2f}")
                    st.metric("Weighted Exfiltration", f"{results['weighted_exfiltration']:.2f}")
                
                with col4:
                    st.metric("Containers Completed", len(results.get('container_completion_times', [])))
                    st.metric("Avg Exfiltration Rate", f"{results.get('avg_exfiltration_rate', 0):.4f}")
                
                # Tenant metrics
                st.subheader("Tenant Metrics")
                tenant_data = []
                for tenant_metric in results.get('tenants', []):
                    tenant_data.append({
                        'Tenant ID': tenant_metric['tenant_id'],
                        'Malicious': tenant_metric['is_malicious'],
                        'Containers': tenant_metric['container_count'],
                        'Total Exfiltration': f"{tenant_metric['total_exfiltration']:.2f}",
                        'Weighted Exfiltration': f"{tenant_metric['weighted_exfiltration']:.2f}"
                    })
                if tenant_data:
                    st.dataframe(pd.DataFrame(tenant_data), use_container_width=True)
        else:
            st.error("Result file not found")
    
    with tab2:
        if result_file.exists():
            st.json(results)
        else:
            st.error("Result file not found")
    
    with tab3:
        if log_file.exists():
            with open(log_file, 'r') as f:
                log_content = f.read()
            st.text_area("Simulation Log", log_content, height=400)
        else:
            st.warning("Log file not found")


def display_multiple_results(scenario, output_dir):
    """Display results from Monte Carlo runs with plots."""
    st.subheader("📊 Monte Carlo Simulation Results")
    
    # Find the summary CSV file
    csv_files = list(output_dir.glob('monte_carlo_summary_*.csv'))
    
    if not csv_files:
        st.warning("Monte Carlo simulation completed but summary files not found yet. Please check the output directory.")
        st.info(f"Output directory: {output_dir}")
        return
    
    csv_file = csv_files[0]
    
    # Load results
    df = pd.read_csv(csv_file)
    
    # Create tabs
    tabs = st.tabs(["Summary Statistics", "Visualizations", "Raw Data"])
    
    with tabs[0]:
        st.subheader("Configuration Overview")
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("Total Configurations", len(df))
            st.metric("Migration Policies", len(df['migration_method_policy'].unique()))
        
        with col2:
            st.metric("Time Budgets Tested", len(df['time_budget'].unique()))
            st.metric("Runtimes Tested", len(df['runtime'].unique()))
        
        st.subheader("Performance by Policy")
        
        policy_stats = df.groupby('migration_method_policy').agg({
            'migrations_mean': 'mean',
            'time_budget_remaining_mean': 'mean',
        }).reset_index()
        
        if scenario == 'malware':
            policy_stats_extra = df.groupby('migration_method_policy').agg({
                'all_types_infected_time_mean': 'mean',
                'infections_cleaned_mean': 'mean',
            }).reset_index()
            policy_stats = policy_stats.merge(policy_stats_extra, on='migration_method_policy')
            
            policy_stats.columns = [
                'Policy', 
                'Avg Migrations', 
                'Avg Budget Remaining (s)',
                'Avg Time to Infect All (s)',
                'Avg Infections Cleaned'
            ]
        else:
            policy_stats_extra = df.groupby('migration_method_policy').agg({
                'weighted_exfiltration_mean': 'mean',
                'total_exfiltration_mean': 'mean',
            }).reset_index()
            policy_stats = policy_stats.merge(policy_stats_extra, on='migration_method_policy')
            
            policy_stats.columns = [
                'Policy',
                'Avg Migrations',
                'Avg Budget Remaining (s)',
                'Avg Weighted Exfiltration',
                'Avg Total Exfiltration'
            ]
        
        st.dataframe(policy_stats, use_container_width=True)
        
        # Top configurations
        st.subheader("🏆 Best Configurations")
        
        if scenario == 'malware':
            # Sort by longest time to infect all types (better defense)
            top_configs = df.nlargest(5, 'all_types_infected_time_mean')[
                ['time_budget', 'runtime', 'migration_method_policy', 
                 'all_types_infected_time_mean', 'migrations_mean', 'infections_cleaned_mean']
            ]
            top_configs.columns = [
                'Time Budget', 'Runtime', 'Policy',
                'Time to Infect All (s)', 'Migrations', 'Infections Cleaned'
            ]
        else:
            # Sort by lowest weighted exfiltration (better defense)
            top_configs = df.nsmallest(5, 'weighted_exfiltration_mean')[
                ['time_budget', 'runtime', 'num_nodes', 'num_tenants',
                 'migration_method_policy', 'weighted_exfiltration_mean', 'migrations_mean']
            ]
            top_configs.columns = [
                'Time Budget', 'Runtime', 'Nodes', 'Tenants',
                'Policy', 'Weighted Exfiltration', 'Migrations'
            ]
        
        st.dataframe(top_configs, use_container_width=True)
    
    with tabs[1]:
        st.subheader("📈 Performance Visualizations")
        
        # Run analysis script to generate plots
        analysis_dir = output_dir / 'analysis'
        
        analysis_script =  Path('scenarios') / scenario / 'analyze_results.py'

        # Check if analysis has been run
        if not analysis_dir.exists():
            with st.spinner("Generating visualizations..."):
                try:
                    subprocess.run(
                        ['python', analysis_script, str(csv_file)],
                        check=True,
                        capture_output=True,
                        text=True,
                        timeout=60
                    )
                except subprocess.TimeoutExpired:
                    st.error("Analysis timed out")
                except Exception as e:
                    st.error(f"Error generating plots: {str(e)}")
        
        # Display plots
        if analysis_dir.exists():
            plot_files = sorted(analysis_dir.glob('*.pdf'))
            
            if plot_files:
                for plot_file in plot_files:
                    st.subheader(plot_file.stem.replace('_', ' ').title())
                    image = convert_from_path(plot_file)[0]
                    st.image(image, use_container_width=True)
            else:
                st.warning("No plot files found")
        else:
            st.warning("Analysis directory not found")
    
    with tabs[2]:
        st.subheader("Raw Data")
        st.dataframe(df, use_container_width=True)
        
        # Download button
        csv_data = df.to_csv(index=False)
        st.download_button(
            label="Download CSV",
            data=csv_data,
            file_name=f"{scenario}_monte_carlo_results.csv",
            mime="text/csv"
        )


def main():
    # Header
    st.markdown('<h1 class="main-header">🔬 SimLiMTD: Simulation with Live Migration for MTD</h1>', 
                unsafe_allow_html=True)
    
    # Sidebar configuration
    st.sidebar.header("💻 Simulation Selection")
    
    # Scenario selection
    scenario = st.sidebar.selectbox(
        "Select Scenario",
        options=['malware', 'exfiltration'],
        format_func=lambda x: x.capitalize(),
        help="Choose between malware infection or data exfiltration simulation"
    )
    
    # Mode selection
    mode = st.sidebar.selectbox(
        "Select Mode",
        options=['single', 'multiple'],
        format_func=lambda x: 'Single Configuration' if x == 'single' else 'Multiple Configurations (Monte Carlo)',
        help="Single: Run one simulation | Multiple: Run Monte Carlo with parameter sweeps"
    )
    
    st.sidebar.markdown("---")
    
    # Microservice Config File Management
    st.sidebar.header("⚙️ Microservice App Configuration")
    
    # Get available configs
    available_configs = get_available_configs()
    
    if not available_configs:
        st.sidebar.warning("No configuration files found. Please upload one.")
        selected_config = None
    else:
        # Config file selector
        config_display_names = [Path(c).name for c in available_configs]
        selected_index = st.sidebar.selectbox(
            "Select Configuration File",
            range(len(available_configs)),
            format_func=lambda i: config_display_names[i],
            help="Choose which microservice configuration to use"
        )
        selected_config = available_configs[selected_index]
        
        # Show config info
        st.sidebar.info(f"📄 Using: {Path(selected_config).name}")
    
    # File upload section
    with st.sidebar.expander("📂 Upload New Config File", expanded=False):
        uploaded_file = st.file_uploader(
            "Choose a JSON configuration file",
            type=['json'],
            help="Upload a custom microservice configuration file",
            key='config_uploader'
        )
        
        if uploaded_file is not None:
            if st.button("Upload & Validate", key='upload_btn'):
                with st.spinner("Uploading and validating..."):
                    file_path, message = save_uploaded_config(uploaded_file)
                    
                    if file_path:
                        st.success(message)
                        st.info(f"File saved as: {Path(file_path).name}")
                        st.rerun()  # Refresh to show new file in dropdown
                    else:
                        st.error(message)
    
    st.sidebar.markdown("---")
    
    # Get default parameters
    defaults = get_default_params(scenario, mode)
    
    # Parameter inputs based on scenario and mode
    st.sidebar.header("📋 Input Parameters")
    params = {}
    
    if mode == 'single':
        # Single configuration parameters
        params['runtime'] = st.sidebar.number_input(
            "Runtime (seconds)",
            min_value=100,
            max_value=100000,
            value=defaults['runtime'],
            step=100,
            help="Total simulation runtime"
        )
        
        params['time_budget'] = st.sidebar.number_input(
            "Time Budget (seconds)",
            min_value=0,
            max_value=50000,
            value=defaults['time_budget'],
            step=50,
            help="Total time budget for migrations"
        )
        
        params['num_nodes'] = st.sidebar.number_input(
            "Number of Nodes",
            min_value=1,
            max_value=50,
            value=defaults['num_nodes'],
            step=1,
            help="Number of physical nodes in the system"
        )
        
        if scenario == 'exfiltration':
            params['num_tenants'] = st.sidebar.number_input(
                "Number of Tenants",
                min_value=2,
                max_value=50,
                value=defaults['num_tenants'],
                step=1,
                help="Total number of tenants (one will be malicious)"
            )
            
            params['malicious_tenant_id'] = st.sidebar.number_input(
                "Malicious Tenant ID",
                min_value=0,
                max_value=params['num_tenants']-1,
                value=min(defaults['malicious_tenant_id'], params['num_tenants']-1),
                step=1,
                help="ID of the malicious tenant"
            )
            
            params['migration_rollback'] = st.sidebar.slider(
                "Migration Rollback",
                min_value=0.0,
                max_value=1.0,
                value=defaults['migration_rollback'],
                step=0.05,
                help="Percentage of exfiltration progress lost during migration"
            )
        
        params['migration_policy'] = st.sidebar.selectbox(
            "Migration Policy",
            options=['random', 'priority_based', 'infected_first'] if scenario == 'malware' else ['random', 'priority_based'],
            index=0,
            help="Policy for selecting which container to migrate"
        )
        
        params['migration_method_policy'] = st.sidebar.selectbox(
            "Migration Method Policy",
            options=['always_precopy', "always_cold", 'min_time'],
            index=0,
            help="Policy for selecting migration method (precopy vs cold)"
        )
        
        st.sidebar.subheader("Migration Period Settings")
        params['auto_migration_period'] = st.sidebar.checkbox(
            "Auto-calculate Migration Period",
            value=defaults.get('auto_migration_period', True),
            help="Automatically calculate migration period based on runtime and time budget"
        )
        
        if not params['auto_migration_period']:
            params['migration_period'] = st.sidebar.number_input(
                "Migration Period (seconds)",
                min_value=1.0,
                max_value=10000.0,
                value=defaults.get('migration_period', 300.0),
                step=10.0,
                help="Period between migrations when auto mode is disabled"
            )
        else:
            params['migration_period'] = 300.0  # Default value (won't be used)
        
        params['seed'] = st.sidebar.number_input(
            "Random Seed",
            min_value=0,
            max_value=1000000,
            value=defaults['seed'],
            step=1,
            help="Random seed for reproducibility"
        )
    
    else:  # multiple config
        st.sidebar.subheader("Time Budget Range")
        col1, col2, col3 = st.sidebar.columns(3)
        with col1:
            params['time_budget_start'] = st.number_input(
                "Start", 
                min_value=0, 
                value=defaults['time_budget_start'],
                key='tb_start'
            )
        with col2:
            params['time_budget_stop'] = st.number_input(
                "Stop", 
                min_value=0, 
                value=defaults['time_budget_stop'],
                key='tb_stop'
            )
        with col3:
            params['time_budget_step'] = st.number_input(
                "Step", 
                min_value=1, 
                value=defaults['time_budget_step'],
                key='tb_step'
            )
        
        st.sidebar.subheader("Runtime Range")
        col1, col2, col3 = st.sidebar.columns(3)
        with col1:
            params['runtime_start'] = st.number_input(
                "Start", 
                min_value=100, 
                value=defaults['runtime_start'],
                key='rt_start'
            )
        with col2:
            params['runtime_stop'] = st.number_input(
                "Stop", 
                min_value=100, 
                value=defaults['runtime_stop'],
                key='rt_stop'
            )
        with col3:
            params['runtime_step'] = st.number_input(
                "Step", 
                min_value=1, 
                value=defaults['runtime_step'],
                key='rt_step'
            )
        
        if scenario == 'exfiltration':
            st.sidebar.subheader("Nodes Range")
            col1, col2, col3 = st.sidebar.columns(3)
            with col1:
                params['nodes_start'] = st.number_input(
                    "Start", 
                    min_value=1, 
                    value=defaults['nodes_start'],
                    key='nodes_start'
                )
            with col2:
                params['nodes_stop'] = st.number_input(
                    "Stop", 
                    min_value=1, 
                    value=defaults['nodes_stop'],
                    key='nodes_stop'
                )
            with col3:
                params['nodes_step'] = st.number_input(
                    "Step", 
                    min_value=1, 
                    value=defaults['nodes_step'],
                    key='nodes_step'
                )
            
            st.sidebar.subheader("Tenants Range")
            col1, col2, col3 = st.sidebar.columns(3)
            with col1:
                params['tenants_start'] = st.number_input(
                    "Start", 
                    min_value=2, 
                    value=defaults['tenants_start'],
                    key='tenants_start'
                )
            with col2:
                params['tenants_stop'] = st.number_input(
                    "Stop", 
                    min_value=2, 
                    value=defaults['tenants_stop'],
                    key='tenants_stop'
                )
            with col3:
                params['tenants_step'] = st.number_input(
                    "Step", 
                    min_value=1, 
                    value=defaults['tenants_step'],
                    key='tenants_step'
                )
            
            st.sidebar.subheader("Rollback Range")
            col1, col2, col3 = st.sidebar.columns(3)
            with col1:
                params['rollback_start'] = st.number_input(
                    "Start", 
                    min_value=0.0, 
                    max_value=1.0,
                    value=defaults['rollback_start'],
                    step=0.05,
                    key='rollback_start'
                )
            with col2:
                params['rollback_stop'] = st.number_input(
                    "Stop", 
                    min_value=0.0, 
                    max_value=1.0,
                    value=defaults['rollback_stop'],
                    step=0.05,
                    key='rollback_stop'
                )
            with col3:
                params['rollback_step'] = st.number_input(
                    "Step", 
                    min_value=0.01, 
                    max_value=1.0,
                    value=defaults['rollback_step'],
                    step=0.05,
                    key='rollback_step'
                )
        
        st.sidebar.subheader("Seed Range")
        col1, col2, col3 = st.sidebar.columns(3)
        with col1:
            params['seed_start'] = st.number_input(
                "Start", 
                min_value=0, 
                value=defaults['seed_start'],
                key='seed_start'
            )
        with col2:
            params['seed_stop'] = st.number_input(
                "Stop", 
                min_value=0, 
                value=defaults['seed_stop'],
                key='seed_stop'
            )
        with col3:
            params['seed_step'] = st.number_input(
                "Step", 
                min_value=1, 
                value=defaults['seed_step'],
                key='seed_step'
            )
        
        st.sidebar.subheader("Migration Period Settings")
        params['auto_migration_period'] = st.sidebar.checkbox(
            "Auto-calculate Migration Period",
            value=defaults.get('auto_migration_period', True),
            help="Automatically calculate migration period based on runtime and time budget",
            key='auto_migration_period'
        )
        
        if not params['auto_migration_period']:
            st.sidebar.subheader("Migration Period Range")
            col1, col2, col3 = st.sidebar.columns(3)
            with col1:
                params['migration_period_start'] = st.number_input(
                    "Start",
                    min_value=1.0,
                    max_value=10000.0,
                    value=defaults.get('migration_period_start', 100.0),
                    step=10.0,
                    key='mp_start'
                )
            with col2:
                params['migration_period_stop'] = st.number_input(
                    "Stop",
                    min_value=1.0,
                    max_value=10000.0,
                    value=defaults.get('migration_period_stop', 500.0),
                    step=10.0,
                    key='mp_stop'
                )
            with col3:
                params['migration_period_step'] = st.number_input(
                    "Step",
                    min_value=1.0,
                    max_value=1000.0,
                    value=defaults.get('migration_period_step', 50.0),
                    step=10.0,
                    key='mp_step'
                )
    
    # Main content area
    st.markdown("---")
    
    # Display configuration summary
    with st.expander("📝 Configuration Summary", expanded=False):
        st.write(f"**Scenario:** {scenario.capitalize()}")
        st.write(f"**Mode:** {'Single Configuration' if mode == 'single' else 'Multiple Configurations (Monte Carlo)'}")
        st.write(f"**Config File:** {Path(selected_config).name if selected_config else 'None selected'}")
        st.write("**Parameters:**")
        for key, value in params.items():
            st.write(f"- {key}: {value}")
    
    # Run button
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        run_button = st.button("🚀 Run Simulation", use_container_width=True, disabled=not selected_config)
    
    # Warning if no config selected
    if not selected_config:
        st.warning("⚠️ Please select or upload a microservice configuration file before running simulations.")
    
    # Run simulation
    if run_button and selected_config:
        with st.spinner(f"Running {scenario} simulation in {mode} mode..."):
            try:
                if mode == 'single':
                    cmd, output_file, log_file = run_single_config(scenario, params, selected_config)
                    
                    # Show command
                    with st.expander("Command", expanded=False):
                        st.code(' '.join(cmd))
                    
                    # Run simulation
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    status_text.text("Initializing simulation...")
                    progress_bar.progress(10)
                    
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=300
                    )
                    
                    progress_bar.progress(90)
                    status_text.text("Processing results...")
                    
                    if result.returncode == 0:
                        progress_bar.progress(100)
                        status_text.text("Simulation completed successfully!")
                        
                        st.markdown('<div class="success-box">✅ Simulation completed successfully!</div>', 
                                  unsafe_allow_html=True)
                        
                        # Display results
                        display_single_results(scenario, output_file, log_file)
                    else:
                        st.markdown('<div class="error-box">❌ Simulation failed!</div>', 
                                  unsafe_allow_html=True)
                        st.error(f"Error: {result.stderr}")
                
                else:  # multiple config
                    cmd, output_dir = run_multiple_config(scenario, params, selected_config)
                    
                    # Show command
                    with st.expander("Command", expanded=False):
                        st.code(' '.join(cmd))
                    
                    # Calculate expected simulations
                    if scenario == 'malware':
                        num_time_budgets = len(range(params['time_budget_start'], 
                                                    params['time_budget_stop'] + 1, 
                                                    params['time_budget_step']))
                        num_runtimes = len(range(params['runtime_start'], 
                                                params['runtime_stop'] + 1, 
                                                params['runtime_step']))
                        num_seeds = len(range(params['seed_start'], 
                                            params['seed_stop'] + 1, 
                                            params['seed_step']))
                        total_sims = num_time_budgets * num_runtimes * 3 * num_seeds  # 2 policies
                    else:
                        num_time_budgets = len(range(params['time_budget_start'], 
                                                    params['time_budget_stop'] + 1, 
                                                    params['time_budget_step']))
                        num_runtimes = len(range(params['runtime_start'], 
                                                params['runtime_stop'] + 1, 
                                                params['runtime_step']))
                        num_nodes = len(range(params['nodes_start'], 
                                            params['nodes_stop'] + 1, 
                                            params['nodes_step']))
                        num_tenants = len(range(params['tenants_start'], 
                                               params['tenants_stop'] + 1, 
                                               params['tenants_step']))
                        num_rollbacks = int((params['rollback_stop'] - params['rollback_start']) / params['rollback_step']) + 1
                        num_seeds = len(range(params['seed_start'], 
                                            params['seed_stop'] + 1, 
                                            params['seed_step']))
                        total_sims = num_time_budgets * num_runtimes * num_nodes * num_tenants * num_rollbacks * 3 * num_seeds
                    
                    st.info(f"This will run approximately {total_sims} simulations. This may take a while...")
                    
                    # Run simulation
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    status_text.text("Running Monte Carlo simulation...")
                    progress_bar.progress(10)
                    
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=3600  # 1 hour timeout for Monte Carlo
                    )
                    print(result.stdout)
                    
                    progress_bar.progress(90)
                    status_text.text("Processing results...")
                    
                    if result.returncode == 0:
                        progress_bar.progress(100)
                        status_text.text("Monte Carlo simulation completed!")
                        
                        st.markdown('<div class="success-box">✅ Monte Carlo simulation completed successfully!</div>', 
                                  unsafe_allow_html=True)
                        
                        # Display results
                        display_multiple_results(scenario, output_dir)
                    else:
                        st.markdown('<div class="error-box">❌ Monte Carlo simulation failed!</div>', 
                                  unsafe_allow_html=True)
                        st.error(f"Error: {result.stderr}")
                        if result.stdout:
                            st.text("Output:")
                            st.text(result.stdout)
            
            except subprocess.TimeoutExpired:
                st.markdown('<div class="error-box">❌ Simulation timed out!</div>', 
                          unsafe_allow_html=True)
                st.error("The simulation took too long and was terminated.")
            
            except Exception as e:
                st.markdown('<div class="error-box">❌ An error occurred!</div>', 
                          unsafe_allow_html=True)
                st.error(f"Error: {str(e)}")
    
    # Information footer
    st.markdown("---")
    with st.expander("ℹ️ About", expanded=False):
        st.markdown("""
        ### SimLiMTD Dashboard
        
        This application provides a user-friendly interface for running Moving Target Defense (MTD) 
        simulations for both malware infection and data exfiltration scenarios.
        
        **Features:**
        - Single configuration runs for testing specific parameters
        - Monte Carlo simulations for comprehensive parameter sweep analysis
        - Automatic visualization generation for Monte Carlo results
        - Real-time progress tracking and result display
        
        **Scenarios:**
        - **Malware:** Models malware infection propagation through containerized applications
        - **Exfiltration:** Models data exfiltration by malicious tenants in multi-tenant environments
        
        **Migration Policies:**
        - **always_precopy:** Always use precopy migration (live migration)
        - **always_cold:** Always use cold migration (live migration)
        - **min_time:** Use fastest migration method based on container type
        
        For more information, see the project documentation.
        """)


if __name__ == '__main__':
    main()
