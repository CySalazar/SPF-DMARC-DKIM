# SPF-DMARC-DKIM
## Introduction
SPF-DMARC-DKIM is a simple program to download SPF, DMARC and DKIM settings.
I wrote SPF-DMARC-DKIM because I needed to check the configurations for SPF, DMARC and DKIM; I had to know if they were set and check the present settings. Searching the net I had found both sites that provided this kind of information and software written mainly in Python.
However, to retrieve DKIM settings data, it was always necessary to specify the selector. Searching the net I found a list of possible selectors, at least the most common ones, which I used to find the one set with a brute-force approach.

## Installation
Just clone the repository and run it with the dotnet run command

## Usage
The project consists of 3 classes (SPF, DMARC and DKIM) plus the base class from which all three derive.

You can use each of these classes in your code as follows:

```
SPF spf = new SPF ();
spf.Domain = Target;
```

The Found property indicates if the setting (in this case for SPF but the operation is the same also for DMARC and DKIM) has been found

```
if (spf.Found)
{
      // SPF found
      Console.WriteLine (spf.Record);
}
else
{
      // SPF not found
}
```

The Record property contains the value of the dns record related to the SPF setting (similarly also for DMARC and DKIM)

## Compatibility
The software is based on .NET Core so is cross-platform

## Requests and Contribution
I am always looking for feedback and requests to improve quality and functionality; for this reason if you need a specific feature and / or want to contribute you will be more than welcome!

## License
SPF-DMARC-DKIM is released under the [MIT license](https://opensource.org/licenses/MIT)

