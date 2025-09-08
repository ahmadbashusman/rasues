import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Patch

# Define phases
attester_phases = ["Attestation response", "Loading keys", "TLS authentication", "IMA log", "UEFI log"]
verifier_phases = ["Attestation request", "Nonce generation", "Loading keys", "TLS authentication", "Verification"]

phases = attester_phases + verifier_phases

# Example data
data = pd.DataFrame({
    "RASUES": [210, 77.32, 116.6, 14, 198.607, 52.5, 19.6, 87.32, 116.6, 296.07],
    "BASELINE": [130, 77.32, 11, 14, 8.607, 52.5, 16, 62, 16, 96.01]
}, index=phases)

roles = ["Attester"]*len(attester_phases) + ["Verifier"]*len(verifier_phases)
colors = {"Attester": "gray", "Verifier": "yellow"}
hatches = {"RASUES": ".", "BASELINE": "///"}

fig, ax = plt.subplots(figsize=(20, 5))
bar_width = 0.4
x = np.arange(len(data))

# Draw horizontal grid lines behind bars
ax.grid(axis='y', linestyle='--', linewidth=0.7, color='gray', zorder=0)

# Plot bars
for i, col in enumerate(["RASUES", "BASELINE"]):
    offset = -bar_width/2 if col == "RASUES" else bar_width/2
    ax.bar(
        x + offset, data[col], width=bar_width,
        color=[colors[role] for role in roles],
        edgecolor="black",
        hatch=hatches[col],
        zorder=3
    )

# Formatting
ax.set_ylabel("Time (ms)", fontsize=20)
ax.set_xticks(x)
ax.set_xticklabels(phases, rotation=15, ha="right", fontsize=15)
#ax.set_title("Attestation Performance: Attester vs Verifier", fontsize=18)  # larger title


margin = 0.1
ax.set_xlim(x[0] - bar_width - margin, x[-1] + bar_width + margin)

# Legend centered above
legend_handles = [
    Patch(facecolor="gray", edgecolor="black", label="Attester"),
    Patch(facecolor="yellow", edgecolor="black", label="Verifier")
]
ax.legend(
    handles=legend_handles,
    loc='upper center',
    bbox_to_anchor=(0.5, .95),
    ncol=2,
    handleheight=2,
    handlelength=3,
    fontsize=14
)

plt.tight_layout()

# Save as high-quality PDF with minimal margins
plt.savefig("attestation_performance.pdf", bbox_inches='tight', dpi=300)

plt.show()



