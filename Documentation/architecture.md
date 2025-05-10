# Application Architecture

This document outlines the architecture of the SPF-DMARC-DKIM .NET Core application. The application is designed to be modular, allowing for easy maintenance and extension.

## 1. Overview

The primary goal of the application is to verify the email security configurations (SPF, DMARC, DKIM) for a given domain. It achieves this by performing DNS lookups for specific record types and, in the case of DKIM, attempting to discover common selectors.

The application is built using C# and .NET Core, ensuring cross-platform compatibility (Windows, macOS, Linux).

## 2. Core Components

The application's logic is primarily encapsulated within a set of specialized classes:

```mermaid
graph TD
    A[Program.cs (Main Entry Point)] --> B(Input Domain)
    B --> C{DNSSec Class}
    C --> D[SPF Class]
    C --> E[DMARC Class]
    C --> F[DKIM Class]
    
    D --> G{DNS Query for SPF}
    E --> H{DNS Query for DMARC}
    F --> I{DNS Query for DKIM (with selector discovery)}
    
    G --> J[SPF Result]
    H --> K[DMARC Result]
    I --> L[DKIM Result]
    
    J --> M{Output Display}
    K --> M
    L --> M
    C --> N[Other DNS Records (TXT, MX, A/AAAA)]
    N --> M

    subgraph DNS Interaction
        G
        H
        I
        N
    end

    subgraph Core Logic Classes
        C
        D
        E
        F
    end
```

### 2.1. `Program.cs`

- **Responsibilities**:
    - Serves as the main entry point of the application.
    - Handles command-line arguments (domain input).
    - Prompts the user for domain input if no argument is provided.
    - Initializes and orchestrates the verification process using the core classes.
    - Displays the results to the user, including record content, detection times, and any errors.
    - Implements a user-friendly spinner during DNS queries.

### 2.2. `DNSSec` Class

- **Responsibilities**:
    - Acts as a base class providing common functionalities for DNS operations and domain string manipulation.
    - Normalizes domain input: handles various formats like full URLs (e.g., `http://example.com`), domains with subdomains, or simple domain names (e.g., `example.com`).
    - Extracts the registrable domain (e.g., `example.com` from `sub.example.com`) to correctly query for DMARC and sometimes SPF records.
    - Manages the `DnsClient` instance used for performing DNS lookups.
    - Provides methods to query for generic DNS record types like TXT, MX, A, and AAAA.
    - Includes basic error handling for DNS queries.

### 2.3. `SPF` Class (Inherits from `DNSSec`)

- **Responsibilities**:
    - Specifically handles the verification of Sender Policy Framework (SPF) records.
    - Constructs the appropriate DNS query for SPF records (typically TXT records at the domain or subdomain level).
    - Parses and validates the retrieved SPF record.
    - Stores the SPF record content and the time taken for detection.
    - Properties: `Found` (boolean), `Record` (string), `TimeToDetectSPF` (TimeSpan).

### 2.4. `DMARC` Class (Inherits from `DNSSec`)

- **Responsibilities**:
    - Handles the verification of Domain-based Message Authentication, Reporting, and Conformance (DMARC) records.
    - Constructs the DNS query for DMARC records (TXT records at `_dmarc.example.com`).
    - Parses and validates the retrieved DMARC record.
    - Stores the DMARC record content and the time taken for detection.
    - Properties: `Found` (boolean), `Record` (string), `TimeToDetectDMARC` (TimeSpan).

### 2.5. `DKIM` Class (Inherits from `DNSSec`)

- **Responsibilities**:
    - Handles the verification of DomainKeys Identified Mail (DKIM) records.
    - Implements the core logic for automatic DKIM selector discovery. This involves:
        - Maintaining a predefined list of common DKIM selectors (e.g., `google`, `selector1`, `default`, `k1`, etc.).
        - Iterating through this list and constructing DNS queries for DKIM records in the format `selector._domainkey.example.com`.
    - Parses and validates any retrieved DKIM records.
    - Stores the found DKIM record, the successful selector, and the time taken for detection.
    - Properties: `Found` (boolean), `Record` (string), `Selector` (string), `TimeToDetectDKIM` (TimeSpan).

## 3. Data Flow

1. **Input**: The user provides a domain name either as a command-line argument or when prompted.
2. **Normalization**: `Program.cs` passes the domain to instances of `SPF`, `DMARC`, and `DKIM` classes. The `DNSSec` base class functionality normalizes the domain.
3. **DNS Queries**:
    - The `SPF` class queries for TXT records at the domain level.
    - The `DMARC` class queries for TXT records at `_dmarc.[domain]`.
    - The `DKIM` class iterates through common selectors, querying for TXT records at `[selector]._domainkey.[domain]`.
    - The `DNSSec` class (via `Program.cs`) also queries for general TXT, MX, and A/AAAA records.
4. **Processing**: Each class processes the DNS responses. If a valid record is found, it's stored along with the detection time.
5. **Output**: `Program.cs` collects the results from all classes and displays them to the user, including whether each record was found, its content, and the time taken.

## 4. Key Libraries and Technologies

- **.NET Core**: The underlying framework, providing cross-platform capabilities.
- **C#**: The programming language used.
- **DnsClient.NET (`DnsClient`)**: A powerful and flexible open-source DNS lookup library for .NET. It is used for all DNS query operations.
- **Standard .NET Libraries**: Used for string manipulation, collections, asynchronous programming (`async`/`await` for DNS queries), etc.

## 5. Error Handling

- DNS query errors (e.g., domain not found, server timeout) are caught and handled gracefully.
- The application will report if a record is not found rather than crashing.
- Input validation ensures that the domain format is reasonable before processing.

## 6. Potential Future Enhancements (Architectural Impact)

- **Batch Processing**: Modifying `Program.cs` to accept a list of domains and loop through the verification process for each.
- **Web/Desktop UI**: Would require a separate UI layer (e.g., ASP.NET Core for web, MAUI/WPF/WinForms for desktop) that interacts with the core logic classes. The core classes are designed to be reusable in such scenarios.
- **Plugin System for Selectors**: Allowing users to provide custom lists of DKIM selectors or integrating with external sources for selectors.
- **Detailed Record Parsing**: Extending the SPF, DMARC, and DKIM classes to parse the record content and provide an interpretation of each tag/mechanism and its implications.

This architecture provides a solid foundation for the current functionality and future growth of the SPF-DMARC-DKIM application.
