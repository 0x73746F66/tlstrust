# Change Log

## 1.0.2 Oct 22th 2021

- Added more positive and negative testing unit test cases
- Removed redundant common name lists from code generators
- Added UNTRUSTED lists to code generators to short circuit complex lookups

## 1.0.1 Oct 22th 2021

- drop fingerprint lookups for all code generators
- all code generators except Apple legacy will index the PEM file
- added `check_trust()`, `exists()`, `expired_in_store()`, and `get_certificate_from_store()` methods
- Method `get_certificate_from_store()` does not support Apple legacy
- Standard logger support
- When Apple legacy is used a `DeprecationWarning` will be logged
- `TrustStore` will now derive a certificate from one of the stores using a supplied Issuer Subject Common Name
- Added an example for use with the requests library

## 0.4.0 Oct 21th 2021

- code generators now sort lists alphabetically
- Now supports common name of the CA Certificate Subject for verification, typically used with TLS clients verifying a server in mTLS mode
- Simplified the api; create teh class with cert bytes or a common name, then check the properties for each store or just check `is_trusted` property

## 0.3.0 Oct 20th 2021

- bug fix for stores module

## 0.2.1 Oct 20th 2021

- Automatically switch off Apple legacy support on April 1 2022
- Support added for Java

## 0.2.0 Oct 20th 2021

- Documentation completed and up-to-date
- CCADB store now directly uses their PEM database rather than the curated Microsoft CSV of signatures
- CCADB store will exclude any CA Certificates with a manual 'distrust from' date set
- Added programming language specific checks, starting with 7 contexts for Python
- Added the `certifi` trust store
- Included a module `tlstrust.certificates` for future use

## 0.1.0 Oct 20th 2021

- Initial release

## 0.0.1 Oct 19th 2021

- Project docs and intent
