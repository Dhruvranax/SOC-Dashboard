import pandas as pd
import os

file_path = r"D:\Dataset\GUIDE_Test.csv"

output_folder = "dataset_parts"
os.makedirs(output_folder, exist_ok=True)

chunk_size = 300000
part = 1

for chunk in pd.read_csv(file_path, chunksize=chunk_size, low_memory=False):

    output_path = os.path.join(
        output_folder,
        f"dataset_part_{part}.csv"
    )

    chunk.to_csv(output_path, index=False)

    print(f"Part {part} created: {len(chunk)} rows")

    part += 1

print("Dataset splitting completed!")