## Trustee manifest file format

The trustee manifest structure is as follows:

* `quorum`: integer representing the "quorum" (minimum number of trustees required for decryption)
* `id`: string representing the trustee's label
* `sequence_number`: integer representing the order this trustee acts in during tallying
* `public_key`: string representing the ECDSA _verifying_ key for this trustee, in base 64. Public and private keys can be
  generated with the script `src/signature-gen.py`
* `private_key`: string representing the ECDSA _signing_ key for this trustee, in base 64. Public and private keys can be
generated with the script `src/signature-gen.py`
* `rabbitmq`: string representing the address to connect to for RabbitMQ (used during ElGamal key generation)
* `directory:` string representing the web address of the directory server
* `others`: array of objects of the following form, representing the other trustees:
    * `id`: string representing the trustee's label
    * `sequence_number`: integer representing the order the trustee acts in during tallying
    * `public_key`: a representing the ECDSA verifying key for the trustee, in base 64

Example files can be found at `data/alice.json`, `data/bob.json`, and `data/charlie.json`.
