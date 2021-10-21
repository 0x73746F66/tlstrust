# Change Log

## 0.4.0 Oct 20th 2021

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
