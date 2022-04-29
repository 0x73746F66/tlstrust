# Change Log

## 2.5.4 Apr 30th 2022

- bug fix for checking if certificates exist in Rustls store

## 2.5.3 Apr 30th 2022

- bug fix for `util.get_store_result_text()`

## 2.5.2 Apr 30th 2022

- Added Rustls trust store
- Added language; Rust
- Added contexts for Rust on platforms; Windows, Apple, Linux
- Added contexts for crates; Rustls, Web PKI

## 2.5.1 Apr 30th 2022

- Added languages; Erlang, Ruby, Go, Node.js
- Added certify trust store contexts for; Erlang, Ruby, Go, Node.js
- Added contexts for new languages on platforms; Windows, Apple, Linux

## 2.5.0 Apr 26th 2022

- support android 13 and 14
- added development hooks and code scans

## 2.4.1 Apr 12th 2022

- support non-standard certificates (like AWS) that do not use a subject common name

## 2.4.0 Apr 11th 2022

- added `.to_dict()` method to `TrustStore` class
- support JSON output for CLI

## 2.3.0 Apr 9th 2022

- support multiple chains and roots for each server leaf

## 2.2.1 Mar 15th 2022

- Added Russian CA store to the `VERSIONS` dictionary

## 2.2.0 Mar 14th 2022

- Added a store for the Russian CA bundle mostly for the CA MinTsifry Rossii, with a few others included also
- The context for Yandex browser now appropriately uses the MinTsifry Rossii store

## 2.1.3 Feb 11th 2022

- Added a lookup dictionary for store versions

## 2.1.2 Feb 11th 2022

- context module usage clean up
- added `all_results` property to `TrustStore`

## 2.1.1 Feb 8th 2022

- Ensure `idna` package is installed, for cli usage only

## 2.1.0 Jan 16th 2022

- Added CLI capability to the library
- `tlstrust.context` provides source context descriptions

## 2.0.4 Jan 16th 2022

- updated to python 3.10 trust store
- Ensures Python 3.9 or newer is used

## 2.0.3 Nov 6th 2021

- Java and Linux versions are no longer hard coded
- Java store extraction now automated
- Point to the Linux store directly, no extraction necessary

## 2.0.2 Nov 6th 2021

- updates to the python certify certs

## 2.0.1 Nov 1st 2021

- Added further Android versions
  - Android 4.4 (KitKat) 2013
  - Android 4 (Ice Cream Sandwich) 2011
  - Android 3 (Honeycomb) 2011
  - Android 2.3 (Gingerbread) 2010
  - Android 2.2 (Froyo) 2010

## 2.0.0 Oct 29th 2021

- Purge `ca_common_name` entirely
- Purge Apple entirely (use 1.x.x for Apple support while it remains available by Apple until April 1, 2022)
- rename `authority_key_identifier` to `key_identifier`
- Use `key_identifier` for Root CA Certificate matching, SKI is authoritative and `ca_common_name` may be false positive match or false negative missing (when the Intermediate in the chain references the Root CA as an issuer but the issuer subject has no CN property)

## 1.1.1 Oct 23rd 2021

- stores are now generated with `__description__` and `__version__`
- Renamed Android store `tlstrust.stores.android` to `tlstrust.stores.android_latest` and now represents the latest android build (unlikely on any devices)
- Added additional Android stores; version 7, 8, 9, 10, 11, 12

Note: `TrustStore.android` still covers all Android versions as it did in previous releases, though now it is more accurately actually covering all Android versions with the inclusion of version specific stores

## 1.1.0 Oct 23rd 2021

- Removed intermediate ca cert from `TrustStore` initial args (was used to derive issuer Root CA, nothing more)
- Added optional `authority_key_identifier` to `TrustStore` initial args
- Require `ca_common_name` for `TrustStore` initial args. Note: `ca_common_name` is used for cert lookup
- Added `match_certificate` using `authority_key_identifier` (fallback to only `ca_common_name` if AKI is missing)

## 1.0.2 Oct 23rd 2021

- Added more positive and negative testing unit test cases
- Removed redundant common name lists from code generators
- Added UNTRUSTED lists to code generators to short circuit complex lookups

## 1.0.1 Oct 22nd 2021

- drop fingerprint lookups for all code generators
- all code generators except Apple legacy will index the PEM file
- added `check_trust()`, `exists()`, `expired_in_store()`, and `get_certificate_from_store()` methods
- Method `get_certificate_from_store()` does not support Apple legacy
- Standard logger support
- When Apple legacy is used a `DeprecationWarning` will be logged
- `TrustStore` will now derive a certificate from one of the stores using a supplied Issuer Subject Common Name
- Added an example for use with the requests library

## 0.4.0 Oct 21st 2021

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
