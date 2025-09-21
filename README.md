# FileIntegrityChecker

This repository contains tools to generate and verify file integrity using SHA-256 hashes. It provides multiple implementations, including a zero-dependency C++ command-line tool and a user-friendly PowerShell GUI for Windows.

Both tools use a "sidecar" approach, creating a separate `.sha256` file to store the hash for a corresponding file.

---

## C++ Command-Line Tool (`main.cpp`)

A zero-dependency, cross-platform command-line tool for checking file integrity, written in C++. It includes a self-contained SHA-256 implementation and can process both files and standard input.

### Features
* **Three Modes of Operation**: Can `hash`, `record`, or `verify` files.
* **Zero-Dependency**: Contains its own "tiny SHA-256" implementation and requires no external libraries.
* **Standard Input**: Can hash data piped directly to it.
* **Sidecar Files**: Creates `.sha256` files for recording and verifying hashes.

### Building
You will need a C++ compiler that supports C++17 (for use of the `<filesystem>` library).

```bash
# Example using g++
g++ -std=c++17 -o ficpp main.cpp

# Example using Clang
clang++ -std=c++17 -o ficpp main.cpp
```

### Usage
The compiled tool takes a command and a file path as arguments.

```bash
./ficpp <command> <path|->
```
* **Commands**:
    * `hash`: Computes and prints the SHA-256 hash of the file or standard input.
    * `record`: Computes the hash and saves it to a sidecar file (e.g., `myfile.txt.sha256`).
    * `verify`: Verifies the file against its `.sha256` sidecar file and reports `OK` or `MISMATCH`.

#### Example Workflow
```bash
# 1. Record the hash of an important file
./ficpp record important.dat
# The tool will output a message like: "wrote: important.dat.sha256"

# 2. Sometime later, verify the file's integrity
./ficpp verify important.dat
# The tool will output: "OK  important.dat"
```

---

## PowerShell GUI Tool (`FileIntegrityUI.ps1`)

A user-friendly graphical tool for Windows users, built with PowerShell and Windows Forms.

### Features
* **Graphical Interface**: Provides an easy-to-use window with buttons for all major functions.
* **File Browser**: Includes a "Browse..." button to easily select files.
* **One-Click Actions**: Simple "Hash", "Record", and "Verify" buttons perform the integrity checks.
* **Clear Output**: Results and errors are displayed in a read-only text box.

### Requirements
* Windows
* PowerShell

### Running the Script
1.  Open a PowerShell terminal.
2.  Navigate to the directory containing the script.
3.  Run the script:
    ```powershell
    .\FileIntegrityUI.ps1
    ```
    *Note: If you encounter an error, you may need to adjust your script execution policy. You can allow scripts for the current session by running `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process`.*

### Usage
1.  Click the **Browse...** button to select a file. The file path will appear in the text box.
2.  Click one of the action buttons:
    * **Hash**: Displays the file's SHA-256 hash in the output box.
    * **Record**: Creates a `.sha256` sidecar file in the same directory as the original file.
    * **Verify**: Compares the file against its `.sha256` sidecar file and shows the result (`OK` or `MISMATCH`).
