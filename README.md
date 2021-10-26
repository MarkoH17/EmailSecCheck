# What is EmailSecCheck?
EmailSecCheck is a lightweight Python utility that checks whether email security DNS records (DMARC and SPF) are configured properly for a domain. EmailSecCheck is powered by [checkdmarc](https://github.com/domainaware/checkdmarc), and leverages it to identify common misconfigurations in DNS records that may enable for email spoofing.

Email spoofing is identified under the following conditions:

 - SPF Issues
   - SPF configured as something other than `fail` or `softfail`
   - SPF record is missing
   - SPF record contains a syntax error
 - DMARC Issues
   - Multiple SPF records exist
   - DMARC record is missing
   - DMARC record contains a syntax error
   - Multiple DMARC records exist


# Getting Started
Grab the latest release and install the package requirements by running `pip3 install -r requirements.txt`. EmailSecCheck was developed for Python 3.

## Checking DNS Records for a Single Domain
```
python3 emailseccheck.py --domain <domain_here>
```

## Checking DNS Records for Several Domains
```
python3 emailseccheck.py --domains_file <path_to_file_here>
```

## Example
![image](https://user-images.githubusercontent.com/8473031/138940399-452c0f6c-3a4d-4b0a-b5dc-f43d7e6245d3.png)

