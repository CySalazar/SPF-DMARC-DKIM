# SPF-DMARC-DKIM

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

A .NET Core application designed to check the email security configurations (SPF, DMARC, and DKIM) of a domain, with a special focus on DKIM, for which it can automatically detect the selector.

## 🔍 Project Philosophy

SPF-DMARC-DKIM was developed out of the need for a practical and versatile tool to quickly verify the configuration of email security protocols for a given domain. The unique aspect of this project, compared to other available solutions, is its ability to automatically detect DKIM selectors through a "brute-force" approach using a list of the most common selectors.

The project's mission is to simplify the process of verifying and diagnosing DNS configurations related to email security, offering a tool that is:

- **Fast**: Provides immediate results with response time indication.
- **Complete**: Checks all three main email security protocols (SPF, DMARC, DKIM).
- **Autonomous**: Does not require prior knowledge of the DKIM selector.
- **Informative**: Also displays other relevant DNS records (TXT, MX, A/AAAA).
- **Cross-platform**: Works on Windows, macOS, and Linux.

## 🛠️ Structure and Implementation

The project is implemented in C# using .NET Core, making it cross-platform. The structure is organized into specialized classes:

- **DNSSec**: Base class that provides common functionality for domain formatting and DNS management.
- **SPF**: Implements verification of SPF records.
- **DMARC**: Implements verification of DMARC records.
- **DKIM**: Implements verification of DKIM records with automatic selector detection.

Each class provides information on detection time, useful for evaluating DNS configuration performance.

The application uses the `DnsClient` library to perform DNS queries and implements a spinner system (graphical display) during queries to enhance the user experience.

### Key Technical Features:

- Automatic handling of various domain input formats (full URLs, IPs, simple domains).
- Support for multi-level TLDs (e.g., .co.uk, .com.br).
- Robust error handling.
- Automatic detection of DKIM selectors from a predefined list.
- Response time measurement for each verification.

## 📚 How to Use the Software

### Prerequisites

- .NET Core 6.0 or higher

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/[username]/SPF-DMARC-DKIM.git
   cd SPF-DMARC-DKIM
   ```
   *(Note: Replace `[username]` with the actual GitHub username if this is a fork or specific repository).*

2. Build the project:
   ```bash
   dotnet build
   ```

### Command-Line Usage

Run the application specifying the domain as an argument:

```bash
dotnet run example.com
```

Or run without arguments and enter the domain when prompted:

```bash
dotnet run
Domain: example.com
```

### Output

The application will display:
- The status of SPF, DMARC, and DKIM records (found or not found).
- The content of the records, if present.
- The time taken to detect each record.
- For DKIM, the selector found and the time taken to find it.
- All TXT, MX, and A/AAAA records associated with the domain.

### Integration into Your Code

The SPF, DMARC, and DKIM classes can also be used independently within another project:

```csharp
// Example of using the SPF class
SPF spf = new SPF();
spf.Domain = "example.com";

if (spf.Found)
{
    Console.WriteLine($"SPF found in {spf.TimeToDetectSPF}ms");
    Console.WriteLine(spf.Record);
}
else
{
    Console.WriteLine("SPF not found");
}

// Similarly for DMARC and DKIM classes
```

## 👥 How to Contribute

Contributions to the project are always welcome! Here's how you can participate:

### Bug Reporting and Feature Requests

- Open an issue on GitHub describing the bug or requested feature.
- Include detailed steps to reproduce the bug or clearly explain the proposed feature.
- If possible, include screenshots or examples.

### Code Contribution

1. Fork the repository.
2. Create a new branch for your modification:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Implement your changes.
4. Ensure the code compiles and works correctly.
5. Run appropriate tests.
6. Commit your changes:
   ```bash
   git commit -m "Added new feature: A brief description of your feature"
   ```
7. Push the branch:
   ```bash
   git push origin feature/your-feature-name
   ```
8. Open a Pull Request.

### Ideas for Contributions

- Add new DKIM selectors to the predefined list.
- Improve error handling and result display.
- Add support for batch verification of multiple domains.
- Implement a web or desktop interface.
- Enhance documentation or add translations.
- Optimize DNS query performance.
- Add detailed analysis of values in records (interpretation of SPF, DMARC, DKIM parameters).

## 📄 License

SPF-DMARC-DKIM is released under the [MIT License](https://opensource.org/licenses/MIT), which allows free use, modification, and distribution of the software, both in personal and commercial projects.
