import sys
import os
import time
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

import pandas as pd
from app.services.network_monitoring import (
    load_dataset_frames,
    _map_to_common_schema,
    combine_dataset_frames,
    COMMON_SCHEMA_COLUMNS
)

def generate_artifact():
    print("=" * 70)
    print("NETSHIELD AI - PRODUCTION DATASET ARTIFACT GENERATOR")
    print("=" * 70)
    
    data_dir = backend_dir / "app" / "data"
    output_parquet = data_dir / "production_traffic.parquet"
    
    print(f"Data directory: {data_dir}")
    print(f"Target output:  {output_parquet}\n")
    
    t0 = time.perf_counter()
    
    # 1. Discover and load raw frames
    print("[1/4] Loading raw CSV/XLSX dataset files...")
    raw_frames, loaded_files, failed_files = load_dataset_frames(data_dir)
    print(f"     Loaded {len(loaded_files)} files. Failed: {len(failed_files)}")
    
    if not raw_frames:
        print("ERROR: No raw dataset files found to process!")
        sys.exit(1)
        
    # 2. Map frames to common schema and apply ML predictions
    print("[2/4] Mapping schema, engineering features & applying ML model predictions...")
    processed_frames = []
    for frame, filepath in zip(raw_frames, loaded_files):
        print(f"     Processing {filepath.name} ({frame.shape[0]} rows)...")
        mapped_frame = _map_to_common_schema(frame)
        processed_frames.append(mapped_frame)
        
    # 3. Combine and deduplicate
    print("[3/4] Combining frames and deduplicating records...")
    combined = combine_dataset_frames(processed_frames)
    print(f"     Combined total rows: {len(combined)}")
    
    # 4. Save to Parquet
    print(f"[4/4] Writing binary parquet artifact to {output_parquet.name}...")
    combined.to_parquet(output_parquet, index=False, compression="snappy")
    
    elapsed = time.perf_counter() - t0
    file_size_mb = output_parquet.stat().st_size / (1024 * 1024)
    
    print("\n" + "=" * 70)
    print("SUCCESSFULLY GENERATED PRODUCTION DATASET ARTIFACT!")
    print(f"Output File : {output_parquet}")
    print(f"Total Rows  : {len(combined):,}")
    print(f"Columns     : {len(combined.columns)}")
    print(f"File Size   : {file_size_mb:.2f} MB")
    print(f"Time Taken  : {elapsed:.2f} seconds")
    print("=" * 70)

if __name__ == "__main__":
    generate_artifact()
