#!/usr/bin/env python3
"""
Analyze Exfiltration Monte Carlo simulation results and generate visualizations.

Usage:
    python scenarios/exfiltration/analyze_results.py results/exfiltration/monte_carlo_summary_*.csv
"""

import sys
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

FONT_SIZE = 17

plt.rcParams.update({
    "font.family": "Helvetica",
    "font.size": FONT_SIZE,
    "legend.fontsize": FONT_SIZE-2,
    "axes.titlesize": FONT_SIZE-1,
    "axes.labelsize": FONT_SIZE-2,
    "xtick.labelsize": FONT_SIZE-2,
    "ytick.labelsize": FONT_SIZE-2,
})

# Optional seaborn import for enhanced visualizations
try:
    import seaborn as sns
    HAS_SEABORN = True
except ImportError:
    HAS_SEABORN = False
    print("Note: seaborn not installed. Using matplotlib only (install with: pip install seaborn)")


def load_results(csv_file: str) -> pd.DataFrame:
    """Load Monte Carlo results from CSV file."""
    df = pd.read_csv(csv_file)
    return df


def plot_time_budget_impact(df: pd.DataFrame, output_dir: Path):
    """Plot impact of time budget on exfiltration metrics."""

    # Plot 1: Time budget vs weighted exfiltration
    fig, ax = plt.subplots(figsize=(6, 3))
    
    for policy in df['migration_method_policy'].unique():
        subset = df[df['migration_method_policy'] == policy]
        time_budget_groups = subset.groupby('time_budget').agg({
            'weighted_exfiltration_mean': 'mean',
            'weighted_exfiltration_std': 'mean'
        }).reset_index()
        ax.errorbar(time_budget_groups['time_budget'], 
                   time_budget_groups['weighted_exfiltration_mean'],
                   yerr=time_budget_groups['weighted_exfiltration_std'],
                   label=policy, marker='o', capsize=3, alpha=0.7, linewidth=2)
    ax.set_xlabel('Time Budget (s)')
    ax.set_ylabel('Avg Weighted Exfiltration')
    #ax.set_title('Weighted Exfiltration vs Time Budget')
    ax.legend()
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    output_file = output_dir / 'time_budget_vs_avg_weighted_exfiltration.pdf'
    plt.savefig(output_file, bbox_inches='tight')
    print(f"Saved plot: {output_file}")
    plt.close()
    
    # Plot 2: Time budget vs migrations
    fig, ax = plt.subplots(figsize=(6, 3))

    for policy in df['migration_method_policy'].unique():
        subset = df[df['migration_method_policy'] == policy]
        time_budget_groups = subset.groupby('time_budget').agg({
            'migrations_mean': 'mean'
        }).reset_index()
        ax.plot(time_budget_groups['time_budget'], 
               time_budget_groups['migrations_mean'],
               label=policy, marker='o', alpha=0.7, linewidth=2)
    ax.set_xlabel('Time Budget (s)')
    ax.set_ylabel('Avg Number of Migrations')
    #ax.set_title('Migrations vs Time Budget')
    ax.legend()
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    output_file = output_dir / 'time_budget_vs_avg_number_of_migrations.pdf'
    plt.savefig(output_file, bbox_inches='tight')
    print(f"Saved plot: {output_file}")
    plt.close()

    # Plot 3: Time budget vs containers completed
    fig, ax = plt.subplots(figsize=(6, 3))

    for policy in df['migration_method_policy'].unique():
        subset = df[df['migration_method_policy'] == policy]
        time_budget_groups = subset.groupby('time_budget').agg({
            'num_completed_mean': 'mean'
        }).reset_index()
        ax.plot(time_budget_groups['time_budget'], 
               time_budget_groups['num_completed_mean'],
               label=policy, marker='o', alpha=0.7, linewidth=2)
    ax.set_xlabel('Time Budget (s)')
    ax.set_ylabel('Average Number of \n Exfiltrated Containers')
    #ax.set_title('Container Completion vs Time Budget')
    ax.legend()
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    output_file = output_dir / 'time_budget_vs_fully_exfiltrated_containers.pdf'
    plt.savefig(output_file, bbox_inches='tight')
    print(f"Saved plot: {output_file}")
    plt.close()
    
    # Plot 4: Efficiency (exfil per migration)
    fig, ax = plt.subplots(figsize=(6, 3))

    for policy in df['migration_method_policy'].unique():
        subset = df[df['migration_method_policy'] == policy]
        # Calculate efficiency: lower exfiltration per migration is better
        subset = subset.copy()
        subset['efficiency'] = subset['weighted_exfiltration_mean'] / (subset['migrations_mean'] + 0.1)
        time_budget_groups = subset.groupby('time_budget').agg({
            'efficiency': 'mean'
        }).reset_index()
        ax.plot(time_budget_groups['time_budget'], 
               time_budget_groups['efficiency'],
               label=policy, marker='o', alpha=0.7, linewidth=2)
    ax.set_xlabel('Time Budget (s)')
    ax.set_ylabel('Weighted Exfiltration per Migration')
    #ax.set_title('Defense Efficiency (Lower is Better)')
    ax.legend()
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    output_file = output_dir / 'time_budget_vs_weighted_exfiltration_per_migration.pdf'
    plt.savefig(output_file, bbox_inches='tight')
    print(f"Saved plot: {output_file}")
    plt.close()


def plot_node_tenant_impact(df: pd.DataFrame, output_dir: Path):
    """Plot impact of node and tenant counts on defense."""

    # Plot 1: Number of nodes vs weighted exfiltration    
    fig, ax = plt.subplots(figsize=(6, 3))

    for policy in df['migration_method_policy'].unique():
        subset = df[df['migration_method_policy'] == policy]
        node_groups = subset.groupby('num_nodes').agg({
            'weighted_exfiltration_mean': 'mean',
            'weighted_exfiltration_std': 'mean'
        }).reset_index()
        ax.errorbar(node_groups['num_nodes'], 
                   node_groups['weighted_exfiltration_mean'],
                   yerr=node_groups['weighted_exfiltration_std'],
                   label=policy, marker='o', capsize=3, alpha=0.7, linewidth=2)
    ax.set_xlabel('Number of Nodes')
    ax.set_ylabel('Avg Weighted Exfiltration')
    #ax.set_title('Weighted Exfiltration vs Node Count')
    ax.legend()
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    output_file = output_dir / 'number_nodes_vs_avg_weighted_exfiltration.pdf'
    plt.savefig(output_file, bbox_inches='tight')
    print(f"Saved plot: {output_file}")
    plt.close()

    # Plot 2: Number of tenants vs weighted exfiltration
    fig, ax = plt.subplots(figsize=(6, 3))

    for policy in df['migration_method_policy'].unique():
        subset = df[df['migration_method_policy'] == policy]
        tenant_groups = subset.groupby('num_tenants').agg({
            'weighted_exfiltration_mean': 'mean',
            'weighted_exfiltration_std': 'mean'
        }).reset_index()
        ax.errorbar(tenant_groups['num_tenants'], 
                   tenant_groups['weighted_exfiltration_mean'],
                   yerr=tenant_groups['weighted_exfiltration_std'],
                   label=policy, marker='o', capsize=3, alpha=0.7, linewidth=2)
    ax.set_xlabel('Number of Tenants')
    ax.set_ylabel('Avg Weighted Exfiltration')
    #ax.set_title('Weighted Exfiltration vs Tenant Count')
    ax.legend()
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    output_file = output_dir / 'num_tenants_vs_avg_weighted_exfiltration.pdf'
    plt.savefig(output_file, bbox_inches='tight')
    print(f"Saved plot: {output_file}")
    plt.close()
    
    # Plot 3: Node-Tenant heatmap for always_precopy
    fig, ax = plt.subplots(figsize=(6, 3))

    subset = df[df['migration_method_policy'] == 'always_precopy']
    pivot = subset.pivot_table(
        values='weighted_exfiltration_mean',
        index='num_nodes',
        columns='num_tenants',
        aggfunc='mean'
    )
    
    if HAS_SEABORN:
        sns.heatmap(pivot, annot=True, fmt='.0f', cmap='RdYlGn_r', ax=ax, 
                   cbar_kws={'label': 'Weighted Exfiltration'})
    else:
        im = ax.imshow(pivot.values, cmap='RdYlGn_r', aspect='auto')
        ax.set_xticks(range(len(pivot.columns)))
        ax.set_yticks(range(len(pivot.index)))
        ax.set_xticklabels(pivot.columns)
        ax.set_yticklabels(pivot.index)
        for i in range(len(pivot.index)):
            for j in range(len(pivot.columns)):
                if not pd.isna(pivot.values[i, j]):
                    ax.text(j, i, f'{pivot.values[i, j]:.0f}',
                           ha="center", va="center", color="black", fontsize=8)
        plt.colorbar(im, ax=ax, label='Weighted Exfiltration')
    
    #ax.set_title('Always PreCopy: Nodes vs Tenants')
    ax.set_xlabel('Number of Tenants')
    ax.set_ylabel('Number of Nodes')

    plt.tight_layout()
    output_file = output_dir / 'num_tenants_vs_num_nodes.pdf'
    plt.savefig(output_file, bbox_inches='tight')
    print(f"Saved plot: {output_file}")
    plt.close()
    
    # Plot 4: Node-Tenant heatmap for min_time
    fig, ax = plt.subplots(figsize=(6, 3))

    subset = df[df['migration_method_policy'] == 'min_time']
    pivot = subset.pivot_table(
        values='weighted_exfiltration_mean',
        index='num_nodes',
        columns='num_tenants',
        aggfunc='mean'
    )
    
    if HAS_SEABORN:
        sns.heatmap(pivot, annot=True, fmt='.0f', cmap='RdYlGn_r', ax=ax,
                   cbar_kws={'label': 'Weighted Exfiltration'})
    else:
        im = ax.imshow(pivot.values, cmap='RdYlGn_r', aspect='auto')
        ax.set_xticks(range(len(pivot.columns)))
        ax.set_yticks(range(len(pivot.index)))
        ax.set_xticklabels(pivot.columns)
        ax.set_yticklabels(pivot.index)
        for i in range(len(pivot.index)):
            for j in range(len(pivot.columns)):
                if not pd.isna(pivot.values[i, j]):
                    ax.text(j, i, f'{pivot.values[i, j]:.0f}',
                           ha="center", va="center", color="black", fontsize=8)
        plt.colorbar(im, ax=ax, label='Weighted Exfiltration')
    
    #ax.set_title('Min Time: Nodes vs Tenants')
    ax.set_xlabel('Number of Tenants')
    ax.set_ylabel('Number of Nodes')

    plt.tight_layout()
    output_file = output_dir / 'num_tenants_vs_num_nodes_heatmap.pdf'
    plt.savefig(output_file, bbox_inches='tight')
    print(f"Saved plot: {output_file}")
    plt.close()


def plot_rollback_impact(df: pd.DataFrame, output_dir: Path):
    """Plot impact of migration rollback percentage."""
    
    # Plot 1: Rollback vs weighted exfiltration
    fig, ax = plt.subplots(figsize=(6, 3))

    for policy in df['migration_method_policy'].unique():
        subset = df[df['migration_method_policy'] == policy]
        rollback_groups = subset.groupby('migration_rollback').agg({
            'weighted_exfiltration_mean': 'mean',
            'weighted_exfiltration_std': 'mean'
        }).reset_index()
        ax.errorbar(rollback_groups['migration_rollback'], 
                   rollback_groups['weighted_exfiltration_mean'],
                   yerr=rollback_groups['weighted_exfiltration_std'],
                   label=policy, marker='o', capsize=3, alpha=0.7, linewidth=2)
    ax.set_xlabel('Migration Rollback (%)')
    ax.set_ylabel('Avg Weighted Exfiltration')
    #ax.set_title('Weighted Exfiltration vs Rollback %')
    ax.legend()
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    output_file = output_dir / 'migration_rollback_vs_avg_weighted_exfiltration.pdf'
    plt.savefig(output_file, bbox_inches='tight')
    print(f"Saved plot: {output_file}")
    plt.close()
    
    # Plot 2: Rollback vs containers completed
    fig, ax = plt.subplots(figsize=(6, 3))

    for policy in df['migration_method_policy'].unique():
        subset = df[df['migration_method_policy'] == policy]
        rollback_groups = subset.groupby('migration_rollback').agg({
            'num_completed_mean': 'mean'
        }).reset_index()
        ax.plot(rollback_groups['migration_rollback'], 
               rollback_groups['num_completed_mean'],
               label=policy, marker='o', alpha=0.7, linewidth=2)
    ax.set_xlabel('Migration Rollback (%)')
    ax.set_ylabel('Avg Containers Fully Exfiltrated')
    #ax.set_title('Container Completion vs Rollback %')
    ax.legend()
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    output_file = output_dir / 'migration_rollback_vs_fully_exfiltrated_containers.pdf'
    plt.savefig(output_file, bbox_inches='tight')
    print(f"Saved plot: {output_file}")
    plt.close()


def plot_policy_comparison(df: pd.DataFrame, output_dir: Path):
    """Compare migration policies across all parameters."""
    
    plot_specs = [
        ('weighted_exfiltration_mean', 'Average Weighted Exfiltration\n (data units)', 'migration_policy_vs_weighted_exfiltration_boxplot.pdf'),
        ('total_exfiltration_mean', 'Average Exfiltration\n (data units)', 'migration_policy_vs_total_exfiltration_boxplot.pdf'),
        ('migrations_mean', 'Avg Number of Migrations', 'migration_policy_vs_num_migrations_boxplot.pdf'),
        ('time_budget_remaining_mean', 'Avg Time Budget Remaining (s)', 'migration_policy_vs_remaining_time_budget_boxplot.pdf'),
    ]

    for column, ylabel, filename in plot_specs:
        fig, ax = plt.subplots(figsize=(6, 3))
        policies = list(df['migration_method_policy'].unique())
        palette_colors = plt.rcParams['axes.prop_cycle'].by_key()['color']
        policy_colors = palette_colors[:len(policies)]

        if HAS_SEABORN:
            palette = dict(zip(policies, policy_colors))
            sns.boxplot(x='migration_method_policy', y=column, data=df, ax=ax,
                        palette=palette)
            sns.stripplot(x='migration_method_policy', y=column, data=df, ax=ax,
                          palette=palette, dodge=True, size=4, jitter=True, alpha=0.6)
        else:
            data = [df[df['migration_method_policy'] == policy][column].dropna().values for policy in policies]
            bp = ax.boxplot(data, tick_labels=policies, patch_artist=True,
                            medianprops=dict(color='#e73c3c'),
                            whiskerprops=dict(color='#4c5e60'),
                            capprops=dict(color='#4c5e60'),
                            flierprops=dict(marker='o', markerfacecolor='black', markersize=4, alpha=0.6))
            for box, color in zip(bp['boxes'], policy_colors):
                box.set_facecolor(color)
                box.set_linewidth(1)

        ax.set_xlabel('Migration Policy')
        ax.set_ylabel(ylabel)
        ax.grid(True, alpha=0.3, axis='y')

        plt.tight_layout()
        output_file = output_dir / filename
        plt.savefig(output_file, bbox_inches='tight')
        print(f"Saved plot: {output_file}")
        plt.close()


def plot_runtime_impact(df: pd.DataFrame, output_dir: Path):
    """Plot impact of runtime on defense effectiveness."""

    # Plot 1: Runtime vs weighted exfiltration
    fig, ax = plt.subplots(figsize=(6, 3))

    for policy in df['migration_method_policy'].unique():
        subset = df[df['migration_method_policy'] == policy]
        runtime_groups = subset.groupby('runtime').agg({
            'weighted_exfiltration_mean': 'mean',
            'weighted_exfiltration_std': 'mean'
        }).reset_index()
        ax.errorbar(runtime_groups['runtime'], 
                   runtime_groups['weighted_exfiltration_mean'],
                   #yerr=runtime_groups['weighted_exfiltration_std'],
                   label=policy, marker='o', capsize=3, alpha=0.7, linewidth=2)
    ax.set_xlabel('Runtime (s)')
    ax.set_ylabel('Average Weighted Exfiltration\n (data units)')
    #ax.set_title('Weighted Exfiltration vs Runtime')
    ax.legend()
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    output_file = output_dir / 'runtime_vs_avg_weighted_exfiltration.pdf'
    plt.savefig(output_file, bbox_inches='tight')
    print(f"Saved plot: {output_file}")
    plt.close()

    # Plot 2: Runtime vs weighted exfiltration
    fig, ax = plt.subplots(figsize=(6, 3))

    for policy in df['migration_method_policy'].unique():
        subset = df[df['migration_method_policy'] == policy]
        runtime_groups = subset.groupby('runtime').agg({
            'total_exfiltration_mean': 'mean',
            'total_exfiltration_std': 'mean'
        }).reset_index()
        ax.errorbar(runtime_groups['runtime'], 
                   runtime_groups['total_exfiltration_mean'],
                   #yerr=runtime_groups['weighted_exfiltration_std'],
                   label=policy, marker='o', capsize=3, alpha=0.7, linewidth=2)
    ax.set_xlabel('Runtime (s)')
    ax.set_ylabel('Average Exfiltration\n (data units)') # Avg Total Exfiltration
    #ax.set_title('Weighted Exfiltration vs Runtime')
    ax.legend()
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    output_file = output_dir / 'runtime_vs_avg_total_exfiltration.pdf'
    plt.savefig(output_file, bbox_inches='tight')
    print(f"Saved plot: {output_file}")
    plt.close()
    
    # Plot 3: Runtime vs exfiltration rate
    fig, ax = plt.subplots(figsize=(6, 3))

    for policy in df['migration_method_policy'].unique():
        subset = df[df['migration_method_policy'] == policy]
        runtime_groups = subset.groupby('runtime').agg({
            'avg_exfiltration_rate_mean': 'mean'
        }).reset_index()
        ax.plot(runtime_groups['runtime'], 
               runtime_groups['avg_exfiltration_rate_mean'],
               label=policy, marker='o', alpha=0.7, linewidth=2)
    ax.set_xlabel('Runtime (s)')
    ax.set_ylabel('Avg Exfiltration Rate (units/s)')
    #ax.set_title('Exfiltration Rate vs Runtime')
    ax.legend()
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    output_file = output_dir / 'runtime_vs_avg_exfiltration_rate.pdf'
    plt.savefig(output_file, bbox_inches='tight')
    print(f"Saved plot: {output_file}")
    plt.close()


def print_summary_statistics(df: pd.DataFrame):
    """Print summary statistics."""
    
    print("\n" + "="*80)
    print("EXFILTRATION MONTE CARLO RESULTS SUMMARY")
    print("="*80)
    
    print(f"\nTotal configurations tested: {len(df)}")
    print(f"Migration policies: {df['migration_method_policy'].unique().tolist()}")
    print(f"Time budgets tested: {sorted(df['time_budget'].unique())}")
    print(f"Runtimes tested: {sorted(df['runtime'].unique())}")
    print(f"Node counts tested: {sorted(df['num_nodes'].unique())}")
    print(f"Tenant counts tested: {sorted(df['num_tenants'].unique())}")
    print(f"Rollback percentages tested: {sorted(df['migration_rollback'].unique())}")
    
    print("\n" + "-"*80)
    print("OVERALL STATISTICS BY POLICY")
    print("-"*80)
    
    for policy in df['migration_method_policy'].unique():
        subset = df[df['migration_method_policy'] == policy]
        
        print(f"\n{policy}:")
        print(f"  Avg weighted exfiltration: {subset['weighted_exfiltration_mean'].mean():.2f}")
        print(f"  Avg total exfiltration: {subset['total_exfiltration_mean'].mean():.2f}")
        print(f"  Avg containers completed: {subset['num_completed_mean'].mean():.2f}")
        print(f"  Avg migrations: {subset['migrations_mean'].mean():.1f}")
        print(f"  Avg time budget remaining: {subset['time_budget_remaining_mean'].mean():.2f}s")
        print(f"  Avg exfiltration rate: {subset['avg_exfiltration_rate_mean'].mean():.4f} units/s")
    
    print("\n" + "-"*80)
    print("BEST CONFIGURATIONS (by lowest weighted exfiltration)")
    print("-"*80)
    
    # Top configurations by weighted exfiltration (lower is better)
    top_configs = df.nsmallest(5, 'weighted_exfiltration_mean')
    
    for i, (_, row) in enumerate(top_configs.iterrows(), 1):
        print(f"\n{i}. TB={row['time_budget']:.0f}s, RT={row['runtime']:.0f}s, Nodes={row['num_nodes']}, "
              f"Tenants={row['num_tenants']}, Rollback={row['migration_rollback']:.1f}, Policy={row['migration_method_policy']}")
        print(f"   Weighted Exfil: {row['weighted_exfiltration_mean']:.2f} ± {row['weighted_exfiltration_std']:.2f}")
        print(f"   Total Exfil: {row['total_exfiltration_mean']:.2f} ± {row['total_exfiltration_std']:.2f}")
        print(f"   Migrations: {row['migrations_mean']:.1f}, Completed: {row['num_completed_mean']:.1f}")
    
    print("\n" + "-"*80)
    print("WORST CONFIGURATIONS (by highest weighted exfiltration)")
    print("-"*80)
    
    # Worst configurations
    worst_configs = df.nlargest(5, 'weighted_exfiltration_mean')
    
    for i, (_, row) in enumerate(worst_configs.iterrows(), 1):
        print(f"\n{i}. TB={row['time_budget']:.0f}s, RT={row['runtime']:.0f}s, Nodes={row['num_nodes']}, "
              f"Tenants={row['num_tenants']}, Rollback={row['migration_rollback']:.1f}, Policy={row['migration_method_policy']}")
        print(f"   Weighted Exfil: {row['weighted_exfiltration_mean']:.2f} ± {row['weighted_exfiltration_std']:.2f}")
        print(f"   Total Exfil: {row['total_exfiltration_mean']:.2f} ± {row['total_exfiltration_std']:.2f}")
        print(f"   Migrations: {row['migrations_mean']:.1f}, Completed: {row['num_completed_mean']:.1f}")
    
    print("\n" + "="*80 + "\n")


def main():
    if len(sys.argv) < 2:
        print("Usage: python scenarios/exfiltration/analyze_results.py <summary.csv>")
        print("\nExample:")
        print("  python scenarios/exfiltration/analyze_results.py results/exfiltration/monte_carlo_summary_*.csv")
        sys.exit(1)
    
    csv_file = sys.argv[1]
    
    # Load results
    print(f"Loading results from: {csv_file}")
    df = load_results(csv_file)
    
    # Create output directory for plots
    output_dir = Path(csv_file).parent / 'analysis'
    output_dir.mkdir(exist_ok=True)
    
    # Print summary statistics
    print_summary_statistics(df)
    
    # Generate plots
    print("\nGenerating visualizations...")
    plot_time_budget_impact(df, output_dir)
    plot_node_tenant_impact(df, output_dir)
    plot_rollback_impact(df, output_dir)
    plot_policy_comparison(df, output_dir)
    plot_runtime_impact(df, output_dir)
    
    print(f"\nAnalysis complete. Plots saved to: {output_dir}")


if __name__ == '__main__':
    main()
