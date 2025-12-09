# Algorithm Analysis & Design Project: GA-XOR vs. AES-256-GCM

This repository contains the source code for a comparative analysis of two encryption algorithms:

1. **GA-XOR (Algorithm 1):** A custom symmetric encryption algorithm that uses Genetic Algorithms (GA) to generate high-entropy keys and XOR diffusion for encryption.  
2. **AES-256-GCM (Algorithm 2):** An industry-standard implementation using the Advanced Encryption Standard with Galois/Counter Mode for authenticated encryption.

---

## 📂 Files Description

### `ga_encrypt.py`
- Implements the Genetic Algorithm (GA) key-generation process and encryption logic.  
- Uses evolutionary strategies (crossover + mutation) to generate high-entropy keys.  
- Encrypts plaintext using XOR and diffusion operations.

### `ga_decrypt.py`
- Contains the decryption logic for the GA-XOR cipher.  
- Reverses diffusion and XOR transformations to recover plaintext.

### `test_cases.py`
- A comprehensive test suite used to compare **GA-XOR** and **AES-256-GCM**.  
- Includes:
  - AES-256-GCM implementation  
  - Test Cases TC-01 to TC-07  
  - Performance measurements and tampering tests

### `sha_256.py`
- Utility script used to compute SHA-256 hashes for integrity verification.

---

## 🔧 Prerequisites

Python 3.x must be installed.

The AES tests require **pycryptodome**:

```bash
pip install pycryptodome
```

> If `pycryptodome` is not installed, AES tests are automatically skipped.

---

## ▶️ How to Run

### **1. Run the Complete Test Suite (Recommended)**

Executes all test cases (TC-01 to TC-07) and prints a comparative summary:

```bash
python test_cases.py
```

---

### **2. Run Individual Modules**

#### 🔐 Encryption

```bash
python ga_encrypt.py
```

You will be prompted to:
- Enter plaintext  
- View output: encrypted binary, encrypted text, GA-generated key (binary + text)

#### 🔓 Decryption

```bash
python ga_decrypt.py
```

Input required:
- Cipher Text  
- Key List (output from encryption)

---

## 🧪 Test Coverage Summary

The `test_cases.py` script evaluates the following:

| ID | Test Case | Description |
|----|-----------|-------------|
| **TC-01** | Happy Path | Checks that decrypt(encrypt(text)) == original text for both algorithms. |
| **TC-02** | Empty Input | Tests behavior for empty strings. |
| **TC-03** | Long Input | Stress test using `"A" * 1000`. |
| **TC-05** | Wrong Key | Modified key should cause decryption failure. |
| **TC-06** | Tampered Cipher | Bit-flip in ciphertext tests data integrity. |
| **TC-07** | Performance | Measures time to generate 100 keys. |

---

## 📝 License

This project was created for academic use as part of the **CIS 505 Algorithm Analysis and Design** course.
