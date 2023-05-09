<img src="https://eeid.ee/images/eis-logo-white.svg" />

# eeID authentication 

<a name="testing"></a>
## Testing

A prerequisite for testing the eeID authentication service is registering a service in test environment. After approving your service, it is possible to test the service immediately, using the credentials generated after approving.

Users for successful authentication:
* Mobile ID phone and id numbers: EE - 00000766 | 60001019906, LT - 60000666 | 50001018865
* Smart-ID personal codes: EE - 30303039914, LV - 030303-10012, LT - 30303039914
* eIDAS country Czech Republic: select Testovací profily from the redirection screen and select a test user for authentication

### ID card

The eeID test environment is directed to the OCSP test service. This means that you need to use a test ID card for authentication or upload your own ID card authentication certificate to the test database:
* The test ID card must be ordered from [SK ID Solutions](https://www.sk.ee/teenused/testkaardid). If it is possible to use your own ID card, ordering a test card is not necessary.
* To use your personal ID card in the test service, you must [upload](https://demo.sk.ee/upload_cert) your authentication certificate. To do this, follow the instructions on the page. After uploading the certificate to the test database, you can test with your personal ID card.

### Mobile ID
The eeID test environment is directed to the Mobiil-ID demo environment. Public test numbers are available for use:
* Test numbers are available [here](https://github.com/SK-EID/MID/wiki/Test-number-for-automated-testing-in-DEMO). Apply only Estonian (EE) test numbers and personal identification codes.

### Smart ID
The eeID test environment is directed to the Smart-ID demo environment. There are two options for use:
* Install the Smart-ID demo application on your device and register a [demo account](https://github.com/SK-EID/smart-id-documentation/wiki/Smart-ID-demo#getting-started).
* Use [test users](https://github.com/SK-EID/smart-id-documentation/wiki/Environment-technical-parameters#test-accounts-for-automated-testing).
