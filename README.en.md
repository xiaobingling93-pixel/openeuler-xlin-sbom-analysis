# XiLing SBOM Analyzer

XiLing SBOM Analyzer is a Docker container-based automated analysis tool for performing security assessments on source code repositories, batches of source code packages, or SBOM files and generating detailed reports. This manual will guide you through building the image and performing scans and analyses.

## System Requirements

- **Docker**: Version 18.09.1 or higher
- **Disk Space**: At least 3GB free space
- **Memory**: 4GB or more recommended

## Loading the Image

If you have obtained the offline image file, please load it as follows:

1.  Obtain the `xiling-analyzer-latest.tar` image file.
2.  Open a terminal and navigate to the directory containing the image file.
3.  Execute the following command to load the image:

```bash
docker load -i xiling-analyzer-latest.tar
```

4.  Verify that the image was loaded successfully:

```bash
docker images | grep xiling-analyzer
```

## Usage Guide

### Scan Mode Overview

Choose one of the following three modes based on your needs:

| Mode | Command Parameter | Input Source | Typical Use Case |
|------|-------------------|--------------|------------------|
| SBOM Analysis | `--sbom` / `-s` | SBOM file (SPDX 2.x) | In-depth analysis based on an existing SBOM |
| Single Repository Scan (in development) | `--repo` / `-r` | Online repository URL | Scanning packages for a specific distribution |
| Batch Scan (in development) | `--batch` / `-b` | Local CSV file | Bulk scanning of multiple specified source code projects |

### Basic Command Structure

All scan modes follow the same basic command format:

```bash
docker run --rm -v <host_output_directory>:/app/output xiling-analyzer:latest <scan_mode> --output /app/output [other_parameters]
```

### Mode 1: SBOM Scan

Perform an in-depth security analysis based on an existing SBOM file.

**Command Format:**
```bash
docker run --rm -v <host_data_directory>:/app/data -v <host_output_directory>:/app/output xiling-analyzer:latest --sbom /app/data/<SBOM_file> --output /app/output
```

**Usage Example:**
```bash
# Linux/Mac
docker run --rm -v $(pwd):/app/data -v $(pwd)/reports:/app/output xiling-analyzer:latest \
  --sbom /app/data/sbom.json \
  --output /app/output

# Windows PowerShell
docker run --rm -v ${PWD}:/app/data -v ${PWD}/reports:/app/output xiling-analyzer:latest \
  --sbom /app/data/sbom.json \
  --output /app/output
```

> **Note**: Currently, only SBOM files in SPDX 2.X format are supported.

## Advanced Configuration

### Using a Configuration File

For users requiring customized scanning behavior, detailed settings can be configured via a JSON configuration file.

**Configuration File Example:**
```json
{
    "general": {
        "report_version": "V1.0", 
        "date_setting": {
            "fixed_date": false,
            "date": "2025-01-01"
        },
        "author": "Alice",
        "reviewer": "Bob",
        "cve_only": true
    }
}
```

**Key Parameter Description:**

| Parameter | Type | Description | Default Value |
|-----------|------|-------------|---------------|
| `general.cve_only` | Boolean | `true`: Show only CVE vulnerabilities; `false`: Show all vulnerabilities | `false` |
| `general.author` | String | Report author information | - |
| `general.reviewer` | String | Report reviewer information | - |

**Command Example Using a Configuration File:**
```bash
# Linux/Mac
docker run --rm -v $(pwd)/reports:/app/output -v $(pwd)/config.json:/app/config.json xiling-analyzer:latest \
  --sbom /app/data/sbom.json \
  --output /app/output \
  --config /app/config.json

# Windows PowerShell
docker run --rm -v ${PWD}/reports:/app/output -v ${PWD}/config.json:/app/config.json xiling-analyzer:latest \
  --sbom /app/data/sbom.json \
  --output /app/output \
  --config /app/config.json
```

### Optional Parameters

- `--max-workers <number>`: Set the maximum number of concurrent threads (default: number of CPU cores)
- `--disable-tqdm`: Disable progress bar display (suitable for automated environments)
- `--config <config_file_path>`: Specify the external configuration file path

## Output Results

Upon completion of the scan, reports will be saved in your specified output directory, containing the following files:

| File/Directory | Format | Description |
|----------------|--------|-------------|
| `Security_Introduction_Assessment_Report.docx` | Word Document | Detailed Word format security assessment report |
| `Security_Introduction_Assessment_Report.pdf` | PDF Document | PDF format report for easy distribution |
| `analysis_output/` | Directory | Contains detailed scan result data |
| &nbsp;&nbsp;├── `vulnerability_scan_results` | JSON File | Detailed vulnerability scan results for all components |
| &nbsp;&nbsp;├── `license_scan_results` | JSON File | License detection and analysis results |
| &nbsp;&nbsp;└── `license_distribution_chart` | PNG Image | Pie chart visualization of license distribution |

## Troubleshooting

### Common Issues

#### Q: "OpenBLAS" error during runtime

**Error Message:**
```bash
OpenBLAS blas_thread_init: pthread_create failed for thread 1 of 12: Operation not permitted
OpenBLAS blas_thread_init: ensure that your address space and process count limits are big enough (ulimit -a)
...
```

**Solution:**
Add the `--security-opt seccomp=unconfined` parameter when running the container:

```bash
docker run --rm --security-opt seccomp=unconfined -v ./reports:/app/output xiling-analyzer:latest \
  --sbom /app/data/sbom.json \
  --output /app/output
```

### Problem Diagnosis Steps

If you encounter technical issues, please troubleshoot using the following steps:

1.  **Check the Docker Environment**
    ```bash
    docker --version
    docker info
    ```

2.  **Verify Image Loading**
    ```bash
    docker images | grep xiling-analyzer
    ```

3.  **Check Directory Permissions**
    - Ensure the mounted directory exists and has read/write permissions.
    - Avoid using system-protected directories (e.g., `/root`, `/system`).

4.  **Verify Input File Formats**
    - CSV files: Check field separators and encoding format.
    - SBOM files: Confirm they are in SPDX 2.X format.

## Getting Support

If you encounter problems while using the tool:

1.  **Review This Document**: First, check if the problem is already addressed in the documentation.
2.  **Check Environment Configuration**: Confirm that the Docker version, disk space, etc., meet the requirements.
3.  **Collect Error Information**: Record the complete error logs and command-line output.
4.  **Provide Environment Details**: Include information such as the operating system, Docker version, and image version.

For further technical support, please provide:
- Complete error message screenshots or logs
- The specific command used
- Sample input files (e.g., CSV file contents)
- Operating system and Docker version information

---

**Happy analyzing!** We welcome your feedback and suggestions for improvement.