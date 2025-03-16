# Advanced Electronic Signature

This project is a software tool designed to emulate a qualified electronic signature process according to the PAdES (PDF Advanced Electronic Signature) standard.

## Applications

The solution consists of two applications:

1. **Signature Application:**

   - **Purpose:** Sign and verify PDF documents using the qualified electronic signature.
   - **Functionality:**
     - Automatically detect a hardware tool (a pendrive) containing an encrypted private RSA key.
     - Prompt the user to enter a PIN to decrypt the private key.
     - Sign the selected PDF document by embedding the signature.
     - Enable verification of the signature by a second user using the associated public key.

2. **Pin Application:**
   - **Purpose:** Generate a pair of RSA keys and securely store the private key.
   - **Functionality:**
     - Generate RSA keys (using a 4096-bit key) with a pseudorandom generator.
     - Encrypt the private key using the AES algorithm (256-bit key derived from the user’s PIN hash).
     - Store the encrypted private key on a pendrive.

Both applications are cross-platform and available on Windows, Linux and MacOS upon compilation.

## Installation and Build

### Prerequisites

- **CMake:** For managing the build process.
- **Doxygen:** For generating the project documentation.
- **C/C++ Compiler:** Compatible with your operating system.
- **OpenSSL:** Implementations of AES, RSA, and SHA as required.

### Building the Project

1. **Clone the Repository:**

2. **Generate Build Files with CMake:**

   ```bash
   mkdir build && cd build
   cmake ..
   ```

3. **Compile the Project:**

   ```bash
   cmake --build .
   ```

4. **Generate Documentation (Optional):**
   ```bash
   doxygen Doxyfile
   ```

## Documentation

- **Doxygen Documentation:**  
  The full code documentation is generated using Doxygen.  
  To generate documentation, run:

  ```bash
  doxygen Doxyfile
  ```

  The output can be found in the `docs/` directory.

  Up-to-date documentation is also available in the GitHub pages environment accessible from this repository.

## Acknowledgements

This project was developed as part of the Security of Computer Systems course.
