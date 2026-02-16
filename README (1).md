# Epic FHIR TEFCA IAS — End-to-End Testing Navigator

Interactive Streamlit app for testing Epic Facilitated FHIR endpoints for the CVS IAS use case.

## Quick Start

```bash
pip install -r requirements.txt
streamlit run epic_fhir_tester.py
```

## What This App Does

Walks you through all 7 steps of the Epic Facilitated FHIR flow — no CVS app needed:

| Step | What Happens |
|------|-------------|
| 1. SMART Discovery | Hit `.well-known/smart-configuration` to get OAuth URLs |
| 2. Build Authorize URL | Construct the browser URL for MyChart login |
| 3. MyChart Login | Log in as test patient (Camila Lopez), capture auth code |
| 4. Generate JWT | Sign a `client_assertion` JWT with your SIT private key |
| 5. Token Exchange | POST auth code + JWT → get access token |
| 6. Query FHIR | Use access token to pull Patient, Conditions, Meds, etc. |
| 7. Results Summary | View progress, inspect responses, see architecture context |

## Test Patient

- **Name:** LOPEZ, CAMILA MARIA
- **DOB:** 09/12/1987
- **MyChart:** `fhircamila` / `epicepic1`
- **Epic Sandbox Org:** `urn:oid:1.2.840.114350.1.13.0.1.7.3.688884.100`

## Key Configuration (pre-filled)

- **Client ID:** `6f7ca437-929b-4022-8bf5-c0af3fbe6bef`
- **Redirect URI:** `https://ddlqa.cvs.com/ul/extrecords`
- **JWKS URL:** `https://sit2-api.cvshealth.com/public/.well-known/jwks.json`
- **FHIR Base:** `https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4/`

## Notes

- Epic Sandbox resets every Monday — test mid-week
- Auth codes expire in ~5 minutes — move quickly through Steps 3-5
- RS384 is recommended for Epic Nexus (TEFCA IAS); ES256 works for App Orchard
- New keys take up to 60 min to sync with Sandbox after upload
