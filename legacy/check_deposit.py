# Check a deposit quickly with pyspec

from eth2spec.phase0.spec import DepositMessage, DepositData, BLSPubkey, Bytes32, BLSSignature, Gwei, Version, Root, compute_domain, compute_signing_root, DOMAIN_DEPOSIT
from eth2spec.utils import bls

assert bls.bls_active

pubkey = BLSPubkey('b776c36018e9d6a8e063c953b7a5d362d5ba02741adb0b14e0b0ff204883ea501813d85dbb70fdb5231368e8af011b5e')
withdrawal_creds = Bytes32('002a8799f001b350777f6ea25689f960962fc71b2083a9b5e80102b316d4a331')
amount = Gwei(32000000000)
signature = BLSSignature('b12af968a0f2b6f55b448dd395a3cc2a88b07f902cbddc1ec735dde573c6cad67c099241c50ce9e856a7a2c6ef3f8f08105d3ed5227bcee0356d3a471748bcd445c4f4471d540b3049fa324d519b0bd13e16dbcb340ebc90f165f005fa81ff7d')
deposit_root = Root('ba066d557b3b27a55ae129f01c569dff5daa9ca8a3e45f13188dcb1ac01cb1c5')

fork_version = Version('0x00000001')

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
