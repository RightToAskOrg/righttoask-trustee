# righttoask-trustee
Trustee server for the RightToAsk project. The trustee server allows distributed key generation, and threshold
decryption of vote tallies.

For the companion directory project, see: [https://github.com/RightToAskOrg/righttoask-directory](https://github.com/RightToAskOrg/righttoask-directory)

## Getting started
1. Create and activate a Python virtual environment. (**Note:** make sure you are using Python 3.8.x.)
```shell
 $ python3 --version
Python 3.8.2
 $ python3 -m venv venv      
 $ source venv/bin/activate
```
2. Install `poetry` (skip this step if you already have Poetry).
```shell
curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python -
```
3. Install the required Python packages. (May take a little while.)
```shell
poetry install
```
4. Install [RabbitMQ](https://rabbitmq.com/) and run the server (e.g. using the `rabbitmq-server` command-line application).

## Creating signing keys
Some sample trustee manifests are provided under the `data/` directory. To create your own, you will need to
generate PyNaCl signature keypairs; a helper script is provided at `src/signature-gen.py`.

## The key ceremony
To jointly generate election keys, create trustee manifests (examples provided under `data/`) and start each of the
trustees. For example, to start the provided `alice` key generator:
```shell
python src/elgamal-gen.py data/alice.json
```
Once all trustees have started, and the key ceremony is complete, each trustee will save its key in `keys/<name>.json`.

## The trustee server
To participate in joint decryption after keys have been generated, run each of the trustee servers. For example, to
start the provided `alice` trustee (configured in the directory to be on port 9000 by default):
```shell
python src/main.py --port 9000 alice
```
Once all trustees are running, votes can be tallied and jointly decrypted using the directory server.

**Note:** currently, this requires all trustees to participate.

## Todo
* Documentation of the Python files
* Documentation of the trustee manifest format
* Complete the share recovery logic
