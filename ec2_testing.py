# on the instance
from tenant_kms import TenantKMSManager

REGION = "eu-west-3"
manager = TenantKMSManager(region_name=REGION)  # no session/profile needed

tenant = "did:web:wallet4agent.com:demo#key-1"

# Ensure/create key, then sign
key_id = manager.create_or_get_key_for_tenant(tenant)
jwk, kid, alg = manager.get_public_key_jwk(key_id)
jwt_token = manager.sign_jwt_with_key(
    key_id,
    header={"typ":"JWT"},                  # alg + kid auto-filled
    payload={"iss": tenant, "sub":"123", "iat": int(__import__("time").time()), "exp": int(__import__("time").time())+300}
)
print("kid:", kid, "alg:", alg)
print("JWT:", jwt_token)
