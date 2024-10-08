 # SSL Certificate Generator

## Overview

This repository contains a script to automate the generation of SSL certificates from an internal Microsoft Certification Authority (CA). The script helps you generate or import Certificate Signing Requests (CSRs), submit them to the CA, and collect the issued certificates.

It greatly speeds up the process of requesting a certificate in seconds as opposed to taking 10 minutes per certificate and server.

## Author

- **Florian Bidabe**

## Reference

This script is inspired by my following post on Stack Overflow:
[Submitting Base64 CSR to a Microsoft CA via cURL](https://stackoverflow.com/questions/31283476/submitting-base64-csr-to-a-microsoft-ca-via-curl)

## Features

- **Generate CSR and Private Key**: Automatically generates a CSR and private key for your server. Please handle cryptographic material adequately (storage, distribution).
- **Import CSR**: Allows you to import an existing CSR.
- **Submit CSR**: Submits the CSR to the internal Microsoft CA.
- **Collect Certificate**: Helps you collect the issued certificate from the CA.
- **Generate SSL Material**: Formats the collected certificate into various formats (PEM, PKCS12).

## Requirements
- **Cygwin**: This was written in Bash for Windows, but you could easily fork it and produce a Unix version of it...
- **OpenSSL**: Required for generating certificates.
- **cURL**: Required for submitting certificates.
- **Clip** (optional): Used for copying the CSR to the clipboard.
- **GNU Email** (optional): Used for sending email notifications.
- **Internet Explorer** (optional): Used for manual certificate retrieval.

## Usage

1. **Define Variables**: Set your internal CA details, certificate template, and other necessary variables in the script.
2. **Run the Script**: Execute the script to start the certificate generation process.

## Important Notes

- **Sensitive Information**: Ensure that sensitive information such as usernames, passwords, and internal CA details are handled securely. Avoid hardcoding sensitive data in the script.
- **Environment Variables**: Consider using environment variables to store sensitive information.
- **Logs**: The script generates logs for each step. Review these logs for troubleshooting and ensure they do not contain sensitive information.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request if you have any suggestions or improvements.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For any questions or issues, please contact Florian Bidabe at [bidabe_f@me.com].

---

Thank you for using the SSL Certificate Generator!