import base64
import json
import sys
import time
import traceback
from collections import defaultdict
from os import path
from typing import NamedTuple

from electionguard.guardian import Guardian
from electionguard.key_ceremony import PublicKeySet, ElectionPartialKeyBackup, ElectionPartialKeyVerification
from electionguard.serializable import read_json, write_json
from electionguard.utils import get_optional
from nacl import encoding
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey, SignedMessage
import pika

EXCHG_PUBKEYS = "exchange_pubkeys"


# Store guardian data. Not to be confused with the much more complex ElectionGuard version.
class GuardianInfo(NamedTuple):
    guardian_id: str
    verify_key: VerifyKey
    seq_number: int


def guardian_queue(guardian_id: str) -> str:
    return f"queue_guardian_{guardian_id}"


# Load the manifest data for this guardian.
def load_manifest():
    with open(sys.argv[1], "r") as file:
        return json.load(file)


# Structure the data for the other guardians usefully.
def load_guardians(other_guardians):
    others = {}
    for i, guardian in enumerate(other_guardians):
        if "sequence_number" not in guardian:
            print(f"`sequence_number` missing from guardian {i + 1}")
            exit(1)
        if not isinstance(guardian["sequence_number"], int):
            print(f"`sequence_number` must be an integer (in guardian {i + 1})")
            exit(1)
        seq_number = guardian["sequence_number"]

        if "id" not in guardian:
            print(f"`id` missing from guardian {i + 1}")
            exit(1)

        try:
            verify_key = VerifyKey(guardian["public_key"], encoder=encoding.Base64Encoder)
        except:
            print(f"Invalid public key for guardian {i + 1} (must be a base-64 encoded EdDSA public key). Details:")
            traceback.print_exc()
            exit(1)

        others[seq_number] = GuardianInfo(
            guardian_id=guardian["id"],
            verify_key=verify_key,
            seq_number=seq_number
        )
    return others


def find_guardian_by(guardians, guardian_id):
    return next(guardian for guardian in guardians.values() if guardian.guardian_id == guardian_id)


def share_pubkeys(sign_key, guardian, channel, queue, others):
    # Generate and sign this guardian's public keys
    pubkeyset = guardian.share_public_keys()
    msg = write_json(pubkeyset)
    signature = sign_key.sign(msg.encode("utf-8"))
    signed_msg = base64.b64encode(signature)
    # Publish them to all other guardians
    channel.basic_publish(exchange=EXCHG_PUBKEYS,
                          routing_key="",
                          body=signed_msg)
    print(f"published pubkey set")

    keys_received = {other.guardian_id: False for other in others.values()}
    keys_received[guardian.object_id] = False

    def recv_pubkey_set(ch, method, _properties, body):
        try:
            signed = SignedMessage(base64.b64decode(body))
            # the signature part is 64 bytes long
            # ref: https://pynacl.readthedocs.io/en/latest/signing/
            pubkeyset = read_json(signed[64:], PublicKeySet)
            keys_received[pubkeyset.owner_id] = True
            if pubkeyset.owner_id != guardian.object_id:
                try:
                    others[pubkeyset.sequence_order].verify_key.verify(signed)
                    guardian.save_guardian_public_keys(pubkeyset)
                    print(f"saved pubkey set for {pubkeyset.owner_id}")
                except BadSignatureError:
                    print(f"failed to verify signature for {pubkeyset.owner_id}")

            if all(keys_received.values()):
                channel.basic_cancel(consumer_tag="pubkey-recv")
        except:
            # Any number of deserialisation problems can occur here
            print("failed to deserialise message")
            traceback.print_exc()
        finally:
            ch.basic_ack(delivery_tag=method.delivery_tag)

    channel.basic_consume(queue=queue, on_message_callback=recv_pubkey_set, consumer_tag="pubkey-recv")
    channel.start_consuming()
    print("public key sharing successful")


def verify_pubkeys(sign_key, guardian, channel, queue, others):
    # Collect received keys
    election_keys = dict(guardian.guardian_election_public_keys().keys())
    auxiliary_keys = dict(guardian.guardian_auxiliary_public_keys().keys())

    verified = {(other.guardian_id, other2.guardian_id): False for other in others.values() for other2 in
                others.values() if other != other2}
    received = {(other.guardian_id, other2.guardian_id): False for other in others.values() for other2 in
                others.values() if other != other2}

    # Broadcast the keys we received
    for other in others.values():
        for other_id in election_keys.keys():
            # Do not bother verifying keys where "for" and "from" are the same, or where "for" is this guardian
            if other_id != guardian.object_id and other_id != other.guardian_id:
                msg = json.dumps({
                    "for": other_id,
                    "from": guardian.object_id,
                    "election": write_json(election_keys[other_id]),
                    "auxiliary": write_json(auxiliary_keys[other_id])
                })
                signature = sign_key.sign(msg.encode("utf-8"))
                signed_msg = base64.b64encode(signature)
                channel.basic_publish(exchange="",
                                      routing_key=guardian_queue(other.guardian_id),
                                      body=signed_msg)

    def recv_pubkey(ch, method, _properties, body):
        try:
            signed = SignedMessage(base64.b64decode(body))
            data = json.loads(signed[64:])
            from_id = data["from"]
            for_id = data["for"]

            received[(from_id, for_id)] = True
            if from_id != guardian.object_id:
                try:
                    find_guardian_by(others, from_id).verify_key.verify(signed)
                    if data["election"] == write_json(election_keys[for_id]) \
                            and data["auxiliary"] == write_json(auxiliary_keys[for_id]):
                        verified[(from_id, for_id)] = True
                        print(f"verified pubkey set received by {from_id} for {for_id}")

                    if all(received.values()):
                        channel.basic_cancel(consumer_tag="pubkey-check")
                except BadSignatureError:
                    print(f"failed to verify signature for {from_id}")
        except:
            # Any number of deserialisation problems can occur here
            print("failed to deserialise message")
            traceback.print_exc()
        finally:
            ch.basic_ack(delivery_tag=method.delivery_tag)

    channel.basic_consume(queue=queue, on_message_callback=recv_pubkey, consumer_tag="pubkey-check")
    channel.start_consuming()

    if all(verified.values()):
        print("pubkey verification successful")
    else:
        print("pubkey verification failed")


def share_backups(sign_key, guardian, channel, queue, others):
    for other in others.values():
        backup = get_optional(guardian.share_election_partial_key_backup(other.guardian_id))
        msg = write_json(backup)
        signature = sign_key.sign(msg.encode("utf-8"))
        signed_msg = base64.b64encode(signature)

        channel.basic_publish(exchange='',
                              routing_key=guardian_queue(other.guardian_id),
                              body=signed_msg)

    received = {other.guardian_id: False for other in others.values()}
    verified = {other.guardian_id: False for other in others.values()}

    def recv_backup(ch, method, _properties, body):
        try:
            signed = SignedMessage(base64.b64decode(body))
            backup = read_json(signed[64:], ElectionPartialKeyBackup)
            received[backup.owner_id] = True

            try:
                find_guardian_by(others, backup.owner_id).verify_key.verify(signed)
                guardian.save_election_partial_key_backup(backup)
                verified[backup.owner_id] = True
                print(f"saved backup for {backup.owner_id}")

                if all(received.values()):
                    channel.basic_cancel(consumer_tag="backup-recv")
            except BadSignatureError:
                print(f"failed to verify signature for {backup.owner_id}")
        except:
            # Any number of deserialisation problems can occur here
            print("failed to deserialise message")
            traceback.print_exc()
        finally:
            ch.basic_ack(delivery_tag=method.delivery_tag)

    channel.basic_consume(queue=queue, on_message_callback=recv_backup, consumer_tag="backup-recv")
    channel.start_consuming()

    if all(verified.values()):
        print("backup sharing successful")
    else:
        print("backup sharing failed")


def verify_backups(sign_key, guardian, channel, queue, others):
    for other in others.values():
        verification = guardian.verify_election_partial_key_backup(other.guardian_id)
        if verification is not None:
            msg = json.dumps({
                "status": True,
                "for": other.guardian_id,
                "from": guardian.object_id,
                "verification": write_json(verification)
            })
        else:
            msg = json.dumps({
                "status": False,
                "for": other.guardian_id,
                "from": guardian.object_id
            })

        signature = sign_key.sign(msg.encode("utf-8"))
        signed_msg = base64.b64encode(signature)
        channel.basic_publish(exchange=EXCHG_PUBKEYS,
                              routing_key="",
                              body=signed_msg)

    all_guardians = list(others.values()) + [GuardianInfo(
        guardian_id=guardian.object_id,
        verify_key=None,
        seq_number=0
    )]
    verified = {(from_id.guardian_id, for_id.guardian_id): False for from_id in all_guardians for for_id in all_guardians
                if from_id != for_id}
    received = {(from_id.guardian_id, for_id.guardian_id): False for from_id in all_guardians for for_id in all_guardians
                if from_id != for_id}

    def recv_verification(ch, method, _properties, body):
        try:
            signed = SignedMessage(base64.b64decode(body))
            data = json.loads(signed[64:])
            status = data["status"]
            from_id = data["from"]
            for_id = data["for"]
            received[(from_id, for_id)] = True

            if from_id != guardian.object_id:
                try:
                    find_guardian_by(others, from_id).verify_key.verify(signed)
                    if status:
                        verification = read_json(data["verification"], ElectionPartialKeyVerification)
                        if verification.verified:
                            guardian.save_election_partial_key_verification(verification)
                            verified[(from_id, for_id)] = verification.verified
                            print(f"{from_id} verified backup from {for_id}")
                        else:
                            print(f"{from_id} failed to verify backup from {for_id}")
                except BadSignatureError:
                    print(f"failed to verify signature for {from_id}")
            else:
                verified[(from_id, for_id)] = True

            if all(received.values()):
                channel.basic_cancel(consumer_tag="backup-check")
        except:
            # Any number of deserialisation problems can occur here
            print("failed to deserialise message")
            traceback.print_exc()
        finally:
            ch.basic_ack(delivery_tag=method.delivery_tag)

    channel.basic_consume(queue=queue, on_message_callback=recv_verification, consumer_tag="backup-check")
    channel.start_consuming()

    if all(verified.values()):
        print("backup verification successful")
    else:
        print("backup verification failed")

    failures = [pair for (pair, success) in verified.items() if not success]
    if failures:
        result = defaultdict(list)
        for (from_id, for_id) in failures:
            result[for_id].append(from_id)
        return result
    else:
        return {}


def main(sign_key, guardian, channel, queue, others):
    share_pubkeys(sign_key, guardian, channel, queue, others)
    verify_pubkeys(sign_key, guardian, channel, queue, others)

    guardian.generate_election_partial_key_backups()
    # Have one guardian deliberately send wrong backups for testing purpsoes
    share_backups(sign_key, guardian, channel, queue, others)
    outcome = verify_backups(sign_key, guardian, channel, queue, others)

    if outcome:
        # failed to verify backups
        return

    key = bytes.fromhex(guardian.publish_joint_key().to_hex())
    signature = base64.b64encode(sign_key.sign(key)[:64])

    print(key)

    output = {
        "guardian": json.loads(write_json(guardian, strip_privates=False)),
        # ElectionGuard doesn't have base 64 encoding for some reason
        "pubkey": {
            "key": base64.b64encode(key).decode(),
            "signatures": {
                guardian.object_id: signature.decode()
            }
        }
    }

    with open(path.join("keys", f"{guardian.object_id}.json"), "w") as file:
        file.write(json.dumps(output, indent=2, sort_keys=True))


def check_exists(manifest, field_name):
    if field_name not in manifest:
        print(f"`{field_name}` missing from manifest")
        exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python elgamal-gen.py <path_to_manifest>.json")
    else:
        # Load and validate manifest
        try:
            manifest = load_manifest()
        except:
            print("Manifest file is not valid JSON. Details:")
            traceback.print_exc()
            exit(1)

        check_exists(manifest, "private_key")
        try:
            sign_key = SigningKey(manifest["private_key"], encoder=encoding.Base64Encoder)
        except:
            print("Private key invalid; should be a 32 byte EdDSA seed, base-64 encoded. Details:")
            traceback.print_exc()
            exit(1)

        check_exists(manifest, "quorum")
        if not isinstance(manifest["quorum"], int):
            print("`quorum` should be an integer")
            exit(1)
        quorum = manifest["quorum"]

        check_exists(manifest, "id")
        guardian_id = manifest["id"]

        check_exists(manifest, "sequence_number")
        if not isinstance(manifest["sequence_number"], int):
            print("`sequence_number` should be an integer")
            exit(1)
        seq_number = manifest["sequence_number"]

        check_exists(manifest, "others")
        if not isinstance(manifest["others"], list):
            print("`others` should be a list")
            exit(1)
        others = load_guardians(manifest["others"])

        check_exists(manifest, "rabbitmq")
        mq_address = manifest["rabbitmq"]

        # Create the guardian object
        guardian = Guardian(guardian_id, seq_number, len(others) + 1, quorum)

        # Create RabbitMQ objects
        connection = pika.BlockingConnection(pika.ConnectionParameters(mq_address))
        channel = connection.channel()

        # Declare a queue we'll use for receiving messages
        queue = guardian_queue(guardian_id)
        channel.queue_declare(queue=queue)
        channel.exchange_declare(exchange=EXCHG_PUBKEYS,
                                 exchange_type="fanout")
        channel.queue_bind(exchange=EXCHG_PUBKEYS, queue=queue)

        # Declare and bind other queues to make sure they're available
        for other in others.values():
            channel.queue_declare(queue=guardian_queue(other.guardian_id))
            channel.queue_bind(exchange=EXCHG_PUBKEYS, queue=guardian_queue(other.guardian_id))

        # Hand over control
        try:
            main(sign_key, guardian, channel, queue, others)
            # Give other processes time to finish
            time.sleep(0.5)
        except:
            traceback.print_exc()

        # Clean up to prevent zombie messages
        channel.queue_delete(queue=queue)
        connection.close()


# Below is some draft stuff for recovering from incorrect backups.

# def share_backups_incorrect(sign_key, guardian, channel, queue, others):
#     for other in others.values():
#         backup = get_optional(guardian.share_election_partial_key_backup(other.guardian_id))
#         backup = ElectionPartialKeyBackup(
#             owner_id=backup.owner_id,
#             designated_id=backup.designated_id,
#             designated_sequence_order=backup.designated_sequence_order,
#             encrypted_value='0' * len(backup.encrypted_value),
#             coefficient_commitments=backup.coefficient_commitments,
#             coefficient_proofs=backup.coefficient_proofs
#         )
#         msg = write_json(backup)
#         signature = sign_key.sign(msg.encode("utf-8"))
#         signed_msg = base64.b64encode(signature)
#
#         channel.basic_publish(exchange="",
#                               routing_key=guardian_queue(other.guardian_id),
#                               body=signed_msg)
#
#     received = {other.guardian_id: False for other in others.values()}
#     verified = {other.guardian_id: False for other in others.values()}
#
#     def recv_backup(ch, method, _properties, body):
#         try:
#             signed = SignedMessage(base64.b64decode(body))
#             backup = read_json(signed[64:], ElectionPartialKeyBackup)
#             received[backup.owner_id] = True
#
#             try:
#                 find_guardian_by(others, backup.owner_id).verify_key.verify(signed)
#                 guardian.save_election_partial_key_backup(backup)
#                 verified[backup.owner_id] = True
#                 print(f"saved backup for {backup.owner_id}")
#
#                 if all(received.values()):
#                     channel.basic_cancel(consumer_tag="backup-recv")
#             except BadSignatureError:
#                 print(f"failed to verify signature for {backup.owner_id}")
#         except:
#             # Any number of deserialisation problems can occur here
#             print("failed to deserialise message")
#             traceback.print_exc()
#         finally:
#             ch.basic_ack(delivery_tag=method.delivery_tag)
#
#     channel.basic_consume(queue=queue, on_message_callback=recv_backup, consumer_tag="backup-recv")
#     channel.start_consuming()
#
#     if all(verified.values()):
#         print("backup sharing successful")
#     else:
#         print("backup sharing failed")
#
#     return [pair for (pair, success) in verified.items() if not success]


# def send_challenges(outcome, sign_key, guardian, channel, queue, others):
#     if not outcome:
#         return
#     print("recovering missing backups...")
#
#     # Tell each other guardian which backups they need to provide challenges for
#     for other in others.values():
#         msg = json.dumps({
#             "sender": guardian.object_id,
#             "challenges": outcome[other.guardian_id]
#         })
#         signature = sign_key.sign(msg.encode("utf-8"))
#         signed_msg = base64.b64encode(signature)
#
#         channel.basic_publish(exchange="",
#                               routing_key=guardian_queue(other.guardian_id),
#                               body=signed_msg)
#
#     # Receive our set of required challenges
#     received_challenges = defaultdict(list)
#     received = {other.guardian_id: False for other in others.values()}
#
#     def recv_challenges(ch, method, _properties, body):
#         nonlocal received_challenges
#         try:
#             signed = SignedMessage(base64.b64decode(body))
#             data = json.loads(signed[64:])
#             sender = data["sender"]
#             received[sender] = True
#
#             challenges = data["challenges"]
#
#             try:
#                 find_guardian_by(others, sender).verify_key.verify(signed)
#                 received_challenges[sender] += challenges
#
#                 if all(received.values()):
#                     channel.basic_cancel(consumer_tag="challenge-recv")
#             except BadSignatureError:
#                 print(f"failed to verify signature for {sender}")
#         except:
#             # Any number of deserialisation problems can occur here
#             print("failed to deserialise message")
#             traceback.print_exc()
#         finally:
#             ch.basic_ack(delivery_tag=method.delivery_tag)
#
#     channel.basic_consume(queue=queue, on_message_callback=recv_challenges, consumer_tag="challenge-recv")
#     channel.start_consuming()
#
#     return received_challenges