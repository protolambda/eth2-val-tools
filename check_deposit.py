# Check a deposit quickly with pyspec

from eth2spec.phase0.spec import DepositMessage, BLSPubkey, Bytes32, BLSSignature, Gwei, Version, compute_domain, compute_signing_root, DOMAIN_DEPOSIT
from eth2spec.utils import bls

assert bls.bls_active

pubkey = BLSPubkey('0x80e7043bfe2ac1e63f0891f20e488747b704e4e718f32dfd97c7cd318400ee7f752747799c2ae8169deee04bfe4adcb0')
withdrawal_creds = Bytes32('0x00c622038d3680ed8fc12b536392bb42731d23f45c1c51d09de462adc19f9f48')
amount = Gwei(32000000000)
signature = BLSSignature('0xa8e65941b18b3cfb324e82a362870f1ebcf733869fffa5b53288066e3cc7483b410644edd74aebb556b8f00cb632106c12846996fcd7ffa493803b2bf4097a9eddbfa37e58c2375c771f20e6778e11f0c5a63e46ade43d8d938feae1bc6e5b51')

fork_version = Version('0x00000121')

deposit_message = DepositMessage(
    pubkey=pubkey,
    withdrawal_credentials=withdrawal_creds,
    amount=amount,
)
domain = compute_domain(domain_type=DOMAIN_DEPOSIT, fork_version=fork_version)
signing_root = compute_signing_root(deposit_message, domain)

if not bls.Verify(pubkey, signing_root, signature):
    print("BAD signature")
else:
    print("GOOD signature")

