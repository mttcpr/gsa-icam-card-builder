# Signing CA CRL Reference

This document describes the revoked certificates on CRLs. Only CRLs with revocation entries are documented here.

Test case numbers are from PACS FRTC v1.4.2 Rev. D. Each scenario has both a Registration phase test (section 2.xx) and a Time of Access phase test (section 5.xx) unless noted otherwise.

---

## ICAMTestCardGen3SigningCA.crl

**Issuer:** ICAM Test Card Signing CA (Gen3)

| Serial | Certificate file | Card | Registration TC | Access TC | Expected outcome |
|---|---|---|---|---|---|
| `600000000000000000CF` | `ICAM_Test_Card_PIV_OCSP_Revoked_Signer_No_Check_Present_gen3.crt` | Card 43 | 2.15.03 | 5.15.03 | **Succeeds / access granted** — `id-pkix-ocsp-nocheck` is present in the OCSP signer cert, so the relying party must not check the signer's own revocation status. The revoked signer goes undetected. |
| `600000000000000000D0` | `ICAM_Test_Card_PIV_OCSP_Revoked_Signer_No_Check_Not_Present_gen3.crt` | Card 44 | 2.15.04 | 5.15.04 | **Fails / access denied** — `id-pkix-ocsp-nocheck` is absent, so the relying party must verify the OCSP signer's revocation status and detects that it is revoked. |
| `6000000000000000012F` | `ICAM_Test_Card_PIV_Revoked_CHUID_Signer_Cert_gen3.crt` | Card 57 | 2.10.10 | 5.10.10 | **Fails / access denied** — The CHUID content signing certificate is revoked; the system must detect this and reject the credential. |
| `60000000000000000137` | `ICAM_Test_Card_PIV_Card_Auth_SP_800-73-4_Revoked_Card_Auth_Cert.crt` | Card 58 | 2.09.11, 2.09.12 / 2.15.06 | 5.09.11, 5.09.12 / 5.15.06 | **Fails / access denied** — The Card Authentication certificate is revoked. 2.09.11/5.09.11 test CRL-based detection; 2.09.12/5.09.12 (also numbered 2.15.06/5.15.06) test the case where OCSP is unavailable and the system falls back to CRL-based detection. |

---

## ICAMTestCardSigningCA.crl

**Issuer:** ICAM Test Card Signing CA (Gen1-2)

| Serial | Certificate file | Card | Registration TC | Access TC | Expected outcome |
|---|---|---|---|---|---|
| `D18FC8F76557A6D1` | `ICAM_Test_Card_PIV_Revoked_Content_Signer_gen1-2.crt` | — | — | — | Gen1-2 content signing certificate that is revoked. Specific FRTC test case numbers not confirmed from available documents. |
| `D18FC8F76557A6D2` | `24_Revoked_Certificates / 3 - ICAM_PIV_Auth_SP_800-73-4.crt` | Card 24 | 2.09.03 | *(none)* | **Registration fails** — The end-entity PIV Authentication certificate is revoked. 2.09.03 is registration-phase only; no Time of Access counterpart exists in the FRTC. |
| `D18FC8F76557A6D3` | `24_Revoked_Certificates / 6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt` | Card 24 | — | — | Card Authentication certificate for Card 24 is also revoked. Specific FRTC test case numbers not confirmed from available documents. |

---

## ICAMRevokedCA.crl

**Issuer:** ICAM Revoked CA (fault bridge root)

**Not created by `mkcadata.sh`** — this CRL is a static fault artifact.

Used by FRTC test cases 2.09.02/5.09.02 ("system recognizes when a second intermediate CA certificate is revoked") and 2.10.09/5.10.09 ("system recognizes when an intermediate certificate in the CHUID signer certificate path is revoked"), both using Card 46 PKI Path 16 ("ICAM Invalid Revoked CA").

| Serial | Certificate file | Registration TC | Access TC | Expected outcome |
|---|---|---|---|---|
| `E5698A39B0B60344` | `bridge/16_ICAM_Revoked_CA_to_ICAM_Test_Card_Bridge_CA.crt` | 2.09.02, 2.10.09 | 5.09.02, 5.10.09 | **Fails / access denied** — An intermediate CA in the certification path is revoked; the system must detect this via CRL and reject the credential. |

The revoked certificate is the bridge CA that chains from the ICAM Revoked CA root (`roots/16_ICAM_Revoked_CA.crt`). The CRL serial match has been verified: `E5698A39B0B60344` appears in both `ICAMRevokedCA.crl` and as the serial of `16_ICAM_Revoked_CA_to_ICAM_Test_Card_Bridge_CA.crt`.
