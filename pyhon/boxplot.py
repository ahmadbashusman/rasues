import pandas as pd
import matplotlib.pyplot as plt

# 1) Build the DataFrame
data = {
    'attester_handle': [10.9, 11.5, 11.4, 12.0, 12.9, 10.2, 14.1, 16.2, 13.5, 9.9,
                        14.0, 11.5, 10.7, 14.1, 12.5, 12.6, 10.3, 1.0, 10.5, 10.9],
    'attester':        [403.7, 417.5, 406.5, 410.4, 415.6, 416.8, 419.5, 418.9, 431.5, 417.1,
                        407.9, 429.1, 406.3, 417.7, 418.8, 409.9, 412.1, 430.1, 400.2, 419.7],
    'verifier':        [198.5, 188.3, 196.0, 194.3, 199.0, 193.6, 200.4, 193.9, 183.4, 193.8,
                        203.5, 190.5, 195.2, 194.1, 209.9, 202.5, 193.9, 202.1, 209.3, 191.3],
    'relying_party':   [259.8, 259.4, 251.3, 267.2, 244.4, 243.5, 268.0, 235.7, 278.3, 264.5,
                        249.6, 241.5, 236.6, 234.6, 239.2, 270.6, 251.3, 248.1, 266.3, 236.4]
}
df = pd.DataFrame(data)

# 2) Plot
plt.figure(figsize=(8, 5))
df.boxplot()
plt.ylabel('Time (ms)')
plt.title('Box Plot of Smart-Home Trigger–Action Metrics')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.show()
