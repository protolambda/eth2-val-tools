# Check a deposit quickly with pyspec

from eth2spec.phase0.spec import DepositMessage, DepositData, BLSPubkey, Bytes32, BLSSignature, Gwei, Version, Root, compute_domain, compute_signing_root, DOMAIN_DEPOSIT
from eth2spec.utils import bls

assert bls.bls_active

pubkey = BLSPubkey('0xa5bd5efcf6960ce6874f581d17c531248865a9d87261ff11240e8c27ac922e8fea42bae190da52f0055baa662b92a5bc')
withdrawal_creds = Bytes32('0x00c1e3add0226c543b1471d127018cd667b4d68ae6dd0ebdf37a05c0de0200ce')
amount = Gwei(32000000000)
signature = BLSSignature('0x8c5739934e16e856afe95ddbdc83a2f39e259af1bf1bb411a1e9b4dcf3bbe710c7c42bb5d922644338c39ebf91d5a0fa034098c10e9aac756cce098c7abcc17966ced3d3ae2bc0fbd3dc0fdb5a9c34c3b9871881c6bf8dcc6c301ca0b64b8db5')
deposit_root = Root('0x6b0c1ae845ea2b54d7a1da21043ec45e4b27532c1a50364009713ab30614068b')

fork_version = Version('0x00000123')

deposit_message = DepositMessage(
    pubkey=pubkey,
    withdrawal_credentials=withdrawal_creds,
    amount=amount,
)
domain = compute_domain(domain_type=DOMAIN_DEPOSIT, fork_version=fork_version)
signing_root = compute_signing_root(deposit_message, domain)

if bls.Verify(pubkey, signing_root, signature):
    print("GOOD signature")
else:
    print("BAD signature")


deposit_data = DepositData(
    pubkey=pubkey,
    withdrawal_credentials=withdrawal_creds,
    amount=amount,
    signature=signature,
)
if deposit_data.hash_tree_root() == deposit_root:
    print("GOOD deposit root")
else:
    print("BAD deposit root")
