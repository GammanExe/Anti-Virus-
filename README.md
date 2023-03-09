# Anti-Virus-
An anti-virus written in cpp. This project helped me write code that actively scanned and made changes to files structures in a linux environment. 
Program scans through files structures and searches for any signatures that may be unwanted. In this case a list of "virus" sigantures is defined.
And if any SHA256 file value is equal to one of the signatures in list, that file is encrypted with AES and put into quarantine.
