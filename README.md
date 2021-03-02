# righttoask-trustee
Trustee server for the RightToAsk project. The trustee server allows distributed key generation, and threshold
decryption of vote tallies.

For the companion directory project, see: [https://github.com/RightToAskOrg/righttoask-directory](https://github.com/RightToAskOrg/righttoask-directory)

## Getting started
1. Create and activate a Python virtual environment.
```shell
 $ python3 -m venv venv      
 $ source venv/bin/activate
```
2. Install `poetry` (skip this step if you already have Poetry).
```shell
$ curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python -
```
3. Ensure the required libraries are installed and available on your system:
    - `libssl-dev`
    - `libgmp-dev`
    - `libmpfr-dev`
4. Install the required Python packages. (May take a little while.)
```shell
$ poetry install
```
5. Install [RabbitMQ](https://rabbitmq.com/) and run the server (e.g. using the `rabbitmq-server` command-line application).

## Creating signing keys
Some sample trustee manifests are provided under the `data/` directory. To create your own, you will need to
generate PyNaCl signature keypairs; a helper script is provided at `src/signature-gen.py`. For example:
```shell
$ source venv/bin/activate  # ensure we are in the virtual environment
$ python src/signature-gen.py
"public_key": "Nf1ax1haxBsWT+kYTbKMcCMfpgncjcNTLgwrX2wWZsM=",
"private_key": "vQn9wmifojizvuLAVGvewuUINwGP/a8HOTZIjX3K9po="
```

## The key ceremony
To jointly generate election keys, create trustee manifests (examples provided under `data/`) and start each of the
trustees. For example, to start the provided `alice` key generator:
```shell
$ source venv/bin/activate # ensure we are in the virtual environment
$ python src/elgamal-gen.py data/alice.json
```
To run the demonstration, start the server in three separate terminals for `alice.json`, `bob.json`,
and `charlie.json`. Once all trustees have started and the key ceremony is complete, each trustee will save its key in `keys/<name>.json`.

## The trustee server
To participate in joint decryption after keys have been generated, run each of the trustee servers. For example, to
start the provided `alice` trustee (configured in the directory to be on port 9000 by default):
```shell
$ source venv/bin/activate # ensure we are in the virtual environment
$ python src/main.py --port 9000 alice
```
To run the test locally, ensure each trustee has been started in a separate terminal and with different ports.
The default configuration has the ports:
 * `alice`: `9000`
 * `bob`: `9001`
 * `charlie`: `9002`

Once all trustees are running, votes can be tallied and jointly decrypted using the directory server.

**Note:** currently, this requires all trustees to be online.

## File formats
Descriptions of the manifest formats used in this project are available in `docs/`. `election-manifest.json` is an
ElectionGuard format; more information [can be found here](https://microsoft.github.io/electionguard-python/0_Configure_Election/).

## Known issues
* In some settings (reproduced on Manjaro Linux, kernel 5.10.15) running Uvicorn with `debug=False` causes the server to
suddenly shut down after responding to requests.

## Todo
* Documentation of the Python code
* Complete the share recovery logic
* RabbitMQ authentication
