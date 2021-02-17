import argparse
import base64
import json
import os
import traceback

from electionguard import group
from electionguard.auxiliary import AuxiliaryKeyPair, AuxiliaryPublicKey
from electionguard.ballot import CiphertextAcceptedBallot
from electionguard.data_store import DataStore
from electionguard.decryption import compute_decryption_share
from electionguard.election import ElectionDescription
from electionguard.election_builder import ElectionBuilder
from electionguard.guardian import Guardian
from electionguard.key_ceremony import ElectionJointKey, CeremonyDetails, ElectionKeyPair, ElectionPartialKeyBackup, \
    ElectionPublicKey, ElectionPartialKeyVerification
from electionguard.serializable import read_json, write_json
from electionguard.tally import CiphertextTally
from fastapi import FastAPI
from nacl import encoding
from nacl.signing import SigningKey
from pydantic import BaseModel
import uvicorn


def load_guardian_key(filename: str) -> (Guardian, dict):
    # Deserialises a DataStore (list of lists) correctly, since the read_json() method doesn't.
    def load_data_store(obj, ty):
        ids = [elem[0] for elem in obj]
        details = [read_json(json.dumps(elem[1]), ty) for elem in obj]
        ret = DataStore()
        ret._store = dict(zip(ids, details))
        return ret

    with open(f"{filename}.json", "r") as file:
        manifest = json.load(file)

        # Deserialising Guardian with read_json(.., Guardian) doesn't work, so do it manually.
        # See issues:
        # - https://github.com/microsoft/electionguard-python/issues/317
        # - https://github.com/microsoft/electionguard-python/issues/316
        guardian_manifest = manifest["guardian"]
        sequence_order = guardian_manifest["sequence_order"]
        ceremony_details = read_json(json.dumps(guardian_manifest["ceremony_details"]), CeremonyDetails)

        guardian = Guardian(guardian_manifest["object_id"], sequence_order, ceremony_details.number_of_guardians, ceremony_details.quorum)
        guardian._auxiliary_keys = read_json(json.dumps(guardian_manifest["_auxiliary_keys"]), AuxiliaryKeyPair)
        guardian._election_keys = read_json(json.dumps(guardian_manifest["_election_keys"]), ElectionKeyPair)
        guardian._backups_to_share = load_data_store(guardian_manifest["_backups_to_share"], ElectionPartialKeyBackup)
        guardian._guardian_auxiliary_public_keys = load_data_store(guardian_manifest["_guardian_auxiliary_public_keys"], AuxiliaryPublicKey)
        guardian._guardian_election_public_keys = load_data_store(guardian_manifest["_guardian_election_public_keys"], ElectionPublicKey)
        guardian._guardian_election_partial_key_backups = load_data_store(guardian_manifest["_guardian_election_partial_key_backups"], ElectionPartialKeyBackup)
        guardian._guardian_election_partial_key_verifications = load_data_store(guardian_manifest["_guardian_election_partial_key_verifications"], ElectionPartialKeyVerification)

        return guardian, manifest["pubkey"]


def load_manifest(filename):
    with open(f"{filename}.json", "r") as file:
        return json.load(file)


def load_election_manifest():
    return ElectionDescription.from_json_file("data/election-manifest")


def check_exists(manifest, field_name):
    if field_name not in manifest:
        print(f"`{field_name}` missing from manifest")
        exit(1)


# Load static data for the server
parser = argparse.ArgumentParser(description="Trustee for the RightToAsk system.")
parser.add_argument("trustee_id", help="The trustee ID to use. Loads key information from 'keys/<trustee_id>.json'.",
                    type=str)
parser.add_argument("--port", help="The port to listen on.", type=int, required=True)
args = parser.parse_args()

trustee_id = args.trustee_id

guardian, pubkey = load_guardian_key(os.path.join("keys", trustee_id))
manifest = load_manifest(os.path.join("data", trustee_id))
directory = manifest["directory"]

election_desc = load_election_manifest()

# ElectionGuard doesn't have a nice way to deserialise keys, unfortunately.
hex_pubkey = base64.b64decode(pubkey["key"]).hex()
pubkey: ElectionJointKey = group.int_to_p(int(hex_pubkey, 16))

builder = ElectionBuilder(
    number_of_guardians=guardian.ceremony_details.number_of_guardians,
    quorum=guardian.ceremony_details.quorum,
    description=election_desc
)
builder.elgamal_public_key = pubkey
(metadata, context) = builder.build()

check_exists(manifest, "private_key")
try:
    sign_key = SigningKey(manifest["private_key"], encoder=encoding.Base64Encoder)
except:
    print("Private key invalid; should be a 32 byte EdDSA seed, base-64 encoded. Details:")
    traceback.print_exc()
    exit(1)

app = FastAPI()
if __name__ == "__main__":
    uvicorn.run("main:app", host="localhost", port=args.port, loop="asyncio")


# FastAPI declarations
class Ciphertexts(BaseModel):
    body: str


@app.get("/share")
def get_dec_share(ciphertexts: Ciphertexts):
    ciphertexts = [read_json(json.dumps(ballot), CiphertextAcceptedBallot) for ballot in json.loads(ciphertexts.body)]
    tally = CiphertextTally("my-tally", metadata, context)
    tally.batch_append(ciphertexts)
    share = compute_decryption_share(guardian, tally, context)
    signature = base64.b64encode(sign_key.sign(write_json(share).encode("utf-8"))[:64]).decode()
    return write_json({"share": share, "signature": signature})


@app.get("/pubkey")
def get_pubkey():
    signature = base64.b64encode(sign_key.sign(write_json(pubkey).encode("utf-8"))[:64]).decode()
    return write_json({"pubkey": pubkey, "signature": signature})
