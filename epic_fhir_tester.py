"""
Epic FHIR TEFCA IAS — End-to-End Testing Navigator
=====================================================
Interactive Streamlit app for testing Epic Facilitated FHIR endpoints
for the CVS IAS use case (Camila Lopez test patient).

Steps covered:
  1. SMART Discovery
  2. Build OAuth Authorize URL
  3. MyChart Login & Auth Code Capture
  4. Generate Client Assertion JWT (with private key)
  5. Token Exchange
  6. Query FHIR Resources
  7. View & Inspect Results
"""

import streamlit as st
import json
import time
import uuid
import base64
import textwrap
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Epic FHIR IAS Tester",
    page_icon="🏥",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Custom CSS
# ---------------------------------------------------------------------------
st.markdown("""
<style>
    .main .block-container { max-width: 1100px; padding-top: 1.5rem; }
    .step-card {
        background: linear-gradient(135deg, #f8f9fc 0%, #eef1f8 100%);
        border-left: 4px solid #4A6CF7;
        border-radius: 8px;
        padding: 1.2rem 1.4rem;
        margin-bottom: 1rem;
    }
    .step-card-active {
        background: linear-gradient(135deg, #eef3ff 0%, #dbe6ff 100%);
        border-left: 4px solid #2d4fd7;
    }
    .step-card-done {
        background: linear-gradient(135deg, #edfcf2 0%, #d4f5e0 100%);
        border-left: 4px solid #22c55e;
    }
    .warn-box {
        background: #fff8e1;
        border-left: 4px solid #f59e0b;
        border-radius: 6px;
        padding: 0.8rem 1rem;
        margin: 0.5rem 0;
        font-size: 0.92rem;
    }
    .info-box {
        background: #e8f4fd;
        border-left: 4px solid #3b82f6;
        border-radius: 6px;
        padding: 0.8rem 1rem;
        margin: 0.5rem 0;
        font-size: 0.92rem;
    }
    .code-label {
        font-size: 0.78rem;
        color: #6b7280;
        margin-bottom: 2px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    div[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #1e293b 0%, #0f172a 100%);
    }
    div[data-testid="stSidebar"] .stMarkdown h1,
    div[data-testid="stSidebar"] .stMarkdown h2,
    div[data-testid="stSidebar"] .stMarkdown h3,
    div[data-testid="stSidebar"] .stMarkdown p,
    div[data-testid="stSidebar"] .stMarkdown li,
    div[data-testid="stSidebar"] .stMarkdown label {
        color: #e2e8f0 !important;
    }
    .patient-card {
        background: #f0fdf4;
        border: 1px solid #bbf7d0;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
    }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Session state defaults
# ---------------------------------------------------------------------------
DEFAULTS = {
    "current_step": 1,
    "fhir_base_url": "https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4/",
    "client_id": "6f7ca437-929b-4022-8bf5-c0af3fbe6bef",
    "redirect_uri": "https://ddlqa.cvs.com/ul/extrecords",
    "scopes": "patient/*.read launch/patient openid fhirUser",
    "jwks_url": "https://sit2-api.cvshealth.com/public/.well-known/jwks.json",
    "auth_code": "",
    "access_token": "",
    "patient_id": "",
    "private_key_pem": "",
    "key_algorithm": "RS256",
    "kid": "6bd2d4b1-c99b-4eb2-99bc-5395e31dd6ad",
    "authorize_endpoint": "",
    "token_endpoint": "",
    "jwt_generated": "",
    "token_response_raw": "",
    "fhir_results": {},
    "smart_config_raw": "",
    "tefca_id_token": "",
}
for k, v in DEFAULTS.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ---------------------------------------------------------------------------
# Sidebar — navigation & config
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("# 🏥 Epic FHIR Tester")
    st.markdown("**TEFCA IAS — CVS Health**")
    st.markdown("---")

    steps = {
        1: "📡  SMART Discovery",
        2: "🔗  Build Authorize URL",
        3: "🔑  MyChart Login & Code",
        4: "📝  Generate JWT",
        5: "🔄  Token Exchange",
        6: "📋  Query FHIR Resources",
        7: "📊  Results & Inspection",
    }

    st.markdown("### Navigation")
    for num, label in steps.items():
        is_current = st.session_state.current_step == num
        prefix = "▶ " if is_current else "  "
        if st.button(f"{prefix}{label}", key=f"nav_{num}", use_container_width=True):
            st.session_state.current_step = num
            st.rerun()

    st.markdown("---")
    st.markdown("### 🧪 Test Patient")
    st.markdown("""
    **LOPEZ, CAMILA MARIA**
    - DOB: 09/12/1987
    - Gender: Female
    - Address: 3268 West Johnson St. Apt 117, Garland, TX 75043
    - Phone: 469-555-5555
    - Email: knixontestemail@epic.com
    
    **MyChart Login (try):**
    - User: `fhircamila`
    - Pass: `epicepic1`
    """)

    st.markdown("---")
    st.markdown("### ⚙️ Environment")
    env = st.selectbox("Target", ["Epic Sandbox (FHIR)", "SIT2"], index=0, label_visibility="collapsed")
    if env == "SIT2":
        st.session_state.fhir_base_url = st.text_input("FHIR Base URL", st.session_state.fhir_base_url)

    st.markdown("---")
    st.markdown("""
    <div style='font-size:0.75rem;color:#94a3b8'>
    ⚠️ Sandbox resets Mondays.<br>
    Plan testing mid-week.<br><br>
    Only the FHIR Sandbox<br>(urn:oid:1.2.840.114350.1.13.0.1.7.3.688884.100)<br>
    supports the full OAuth + FHIR flow.
    </div>
    """, unsafe_allow_html=True)

step = st.session_state.current_step

# ===================================================================
# STEP 1 — SMART Discovery
# ===================================================================
if step == 1:
    st.markdown("## Step 1: SMART Discovery")
    st.markdown("""
    <div class='info-box'>
    Hit the FHIR server's <code>.well-known/smart-configuration</code> endpoint to discover
    the OAuth <strong>authorization</strong> and <strong>token</strong> URLs.
    This is the starting point — everything else depends on these URLs.
    </div>
    """, unsafe_allow_html=True)

    fhir_base = st.text_input("FHIR Base URL (from $match response)", st.session_state.fhir_base_url)
    st.session_state.fhir_base_url = fhir_base
    smart_url = fhir_base.rstrip("/") + "/.well-known/smart-configuration"

    st.markdown(f"<p class='code-label'>Request</p>", unsafe_allow_html=True)
    st.code(f"GET {smart_url}", language="http")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**How to run:** Open this URL in your browser or Postman. Copy the JSON response below.")

    with col2:
        st.markdown("""
        <div class='warn-box'>
        💡 <strong>Tip:</strong> In Postman, no auth headers needed for this call.
        Just GET the URL and you'll get back the OAuth endpoint URLs.
        </div>
        """, unsafe_allow_html=True)

    smart_json = st.text_area(
        "Paste the smart-configuration JSON response here:",
        value=st.session_state.smart_config_raw,
        height=200,
        placeholder='{\n  "authorization_endpoint": "https://fhir.epic.com/.../oauth2/authorize",\n  "token_endpoint": "https://fhir.epic.com/.../oauth2/token",\n  ...\n}'
    )
    st.session_state.smart_config_raw = smart_json

    if smart_json.strip():
        try:
            config = json.loads(smart_json)
            auth_ep = config.get("authorization_endpoint", "")
            token_ep = config.get("token_endpoint", "")
            st.session_state.authorize_endpoint = auth_ep
            st.session_state.token_endpoint = token_ep
            st.success(f"✅ Parsed successfully!")
            c1, c2 = st.columns(2)
            with c1:
                st.text_input("Authorization Endpoint", auth_ep, disabled=True)
            with c2:
                st.text_input("Token Endpoint", token_ep, disabled=True)
        except json.JSONDecodeError:
            st.error("Invalid JSON — paste the full response from Postman/browser.")

    if not st.session_state.authorize_endpoint:
        st.markdown("**Or enter manually:**")
        c1, c2 = st.columns(2)
        with c1:
            st.session_state.authorize_endpoint = st.text_input(
                "Authorization Endpoint",
                value="https://fhir.epic.com/interconnect-fhir-oauth/oauth2/authorize",
                key="manual_auth_ep"
            )
        with c2:
            st.session_state.token_endpoint = st.text_input(
                "Token Endpoint",
                value="https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token",
                key="manual_token_ep"
            )

    st.markdown("---")
    if st.button("Next → Build Authorize URL", type="primary"):
        st.session_state.current_step = 2
        st.rerun()


# ===================================================================
# STEP 2 — Build Authorize URL
# ===================================================================
elif step == 2:
    st.markdown("## Step 2: Build the OAuth Authorize URL")
    st.markdown("""
    <div class='info-box'>
    Construct the URL that will redirect the test patient to Epic's MyChart login screen.
    You paste this URL into your <strong>browser</strong> — not Postman.
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        auth_ep = st.text_input("Authorization Endpoint", st.session_state.authorize_endpoint)
        client_id = st.text_input("Client ID", st.session_state.client_id)
        redirect_uri = st.text_input("Redirect URI", st.session_state.redirect_uri)
    with col2:
        scopes = st.text_input("Scopes", st.session_state.scopes)
        state_val = st.text_input("State (any random string)", "test123")
        aud = st.text_input("Audience (FHIR base URL)", st.session_state.fhir_base_url)

    st.session_state.client_id = client_id
    st.session_state.redirect_uri = redirect_uri
    st.session_state.scopes = scopes

    # TEFCA IAS extension parameters
    st.markdown("---")
    st.markdown("#### 🔐 TEFCA IAS Extension (CLEAR id_token)")
    st.markdown("""
    <div class='info-box'>
    For TEFCA IAS, the authorize URL needs the CLEAR identity proofing token.
    In <strong>Epic Sandbox</strong>, fake CSP tokens are accepted.
    In <strong>SIT / Production</strong>, this must be a real CLEAR OIDC id_token.<br><br>
    The Accounts Team provides this token — it proves the patient (Camila Lopez) was identity-proofed to IAL2.
    </div>
    """, unsafe_allow_html=True)

    include_tefca = st.checkbox("Include TEFCA IAS parameters in authorize URL", value=True)
    tefca_purpose = ""
    tefca_id_token = ""

    if include_tefca:
        col_t1, col_t2 = st.columns([1, 3])
        with col_t1:
            tefca_purpose = st.text_input("Purpose of Use", "T-IAS")
        with col_t2:
            tefca_id_token = st.text_area(
                "CLEAR id_token (from Accounts Team)",
                value=st.session_state.get("tefca_id_token", ""),
                height=80,
                placeholder="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJMYlJWOHJ1UmM3UzlxekZlWnpsS2ZneTc4SW11Y0RBbmhmczhuaVhwclciLCJnaXZlbl9uYW1lIjoiQ0FNSUxBIi4uLg..."
            )
            st.session_state["tefca_id_token"] = tefca_id_token

        if not tefca_id_token:
            st.markdown("""
            <div class='warn-box'>
            ⚠️ <strong>No id_token provided.</strong> For Epic Sandbox, this may still work 
            (fake CSP tokens accepted). For SIT, you need the real CLEAR token from the Accounts Team.
            Ask them for the token they generated for test patient Camila Lopez.
            </div>
            """, unsafe_allow_html=True)

    import urllib.parse
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scopes,
        "state": state_val,
        "aud": aud,
    }
    if include_tefca and tefca_purpose:
        params["tefca_ias.purpose"] = tefca_purpose
    if include_tefca and tefca_id_token:
        params["tefca_ias.id_token"] = tefca_id_token

    full_url = auth_ep + "?" + urllib.parse.urlencode(params)

    st.markdown(f"<p class='code-label'>Generated Authorize URL</p>", unsafe_allow_html=True)
    st.code(full_url, language="text")

    st.markdown("""
    <div class='warn-box'>
    📋 <strong>Copy this URL and paste it into your browser.</strong>
    You'll see the Epic MyChart login screen. After logging in & approving,
    you'll be redirected to the redirect URI with a <code>?code=XXX</code> parameter.
    <br><br>
    ⚠️ The page at the redirect URI <strong>won't load</strong> — that's expected!
    Just grab the <code>code</code> value from the browser address bar.
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("← Back", key="b2"):
            st.session_state.current_step = 1
            st.rerun()
    with c2:
        if st.button("Next → MyChart Login & Code Capture", type="primary", key="n2"):
            st.session_state.current_step = 3
            st.rerun()


# ===================================================================
# STEP 3 — MyChart Login & Auth Code Capture
# ===================================================================
elif step == 3:
    st.markdown("## Step 3: MyChart Login & Auth Code Capture")

    st.markdown("""
    <div class='patient-card'>
    <strong>🧑‍⚕️ Test Patient: LOPEZ, CAMILA MARIA</strong><br>
    DOB: 09/12/1987 &nbsp;|&nbsp; Gender: Female &nbsp;|&nbsp; Garland, TX 75043<br>
    MyChart: <code>fhircamila</code> / <code>epicepic1</code>
    &nbsp;(if that doesn't work, check <a href="https://fhir.epic.com/Documentation?docId=testpatients" target="_blank">Epic Sandbox Test Data</a>)
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    ### What to do:
    1. After pasting the Authorize URL in your browser, you should see the **MyChart login screen**
    2. Enter the test patient credentials above
    3. **Approve** the app when prompted (allow CVS to access records)
    4. You'll be redirected — the page **won't load** (that's fine!)
    5. **Quickly copy the entire URL** from the browser address bar
    """)

    redirect_url = st.text_input(
        "Paste the full redirect URL from your browser:",
        placeholder="https://ddlqa.cvs.com/ul/extrecords?code=XXXXXXXX&state=test123",
    )

    if redirect_url:
        try:
            parsed = urllib.parse.urlparse(redirect_url)
            qs = urllib.parse.parse_qs(parsed.query)
            code = qs.get("code", [""])[0]
            if code:
                st.session_state.auth_code = code
                st.success(f"✅ Auth code extracted! (`{code[:20]}...`)")
                st.markdown("""
                <div class='warn-box'>
                ⏱ <strong>This code expires in ~5 minutes!</strong>
                Move to Step 4 (Generate JWT) quickly, or be prepared to redo this step for a fresh code.
                </div>
                """, unsafe_allow_html=True)
            else:
                st.error("No `code` parameter found in the URL. Make sure you copied the full redirect URL.")
        except Exception as e:
            st.error(f"Could not parse URL: {e}")

    st.markdown("**Or paste just the auth code:**")
    manual_code = st.text_input("Auth Code (manual)", st.session_state.auth_code, key="manual_code")
    st.session_state.auth_code = manual_code

    st.markdown("---")

    st.markdown("""
    <div class='warn-box'>
    🔄 <strong>Alternative: Network Tab Trick</strong><br>
    Open Chrome DevTools (F12) → Network tab <em>before</em> clicking the authorize URL.
    After MyChart login & approval, the redirect will show in the Network tab even
    if the page doesn't load. Look for the request to your redirect URI and grab the
    <code>code</code> from its query parameters.
    </div>
    """, unsafe_allow_html=True)

    c1, c2 = st.columns(2)
    with c1:
        if st.button("← Back", key="b3"):
            st.session_state.current_step = 2
            st.rerun()
    with c2:
        if st.button("Next → Generate JWT", type="primary", key="n3"):
            st.session_state.current_step = 4
            st.rerun()


# ===================================================================
# STEP 4 — Generate Client Assertion JWT
# ===================================================================
elif step == 4:
    st.markdown("## Step 4: Generate Client Assertion JWT")
    st.markdown("""
    <div class='info-box'>
    Epic uses <strong>asymmetric JWT authentication</strong> (SMART Backend Services).
    You sign a JWT with your <strong>private key</strong>; Epic verifies it against
    the public key at your <strong>JWKS URI</strong>.
    <br><br>
    Your SIT JWKS: <code>sit2-api.cvshealth.com/public/.well-known/jwks.json</code>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class='warn-box'>
    ⚠️ <strong>Critical:</strong> The signing algorithm <strong>must match</strong> what's declared 
    in your JWKS key (<code>"alg"</code> field). A mismatch (e.g., signing with RS384 when JWKS says RS256) 
    will cause <code>invalid_grant</code>. Click <strong>Detect from JWKS</strong> below to auto-detect.
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        alg = st.selectbox("Signing Algorithm", ["RS256", "RS384", "ES256", "ES384", "RS512"], index=0)
        st.session_state.key_algorithm = alg
        kid = st.text_input("Key ID (kid) — from your JWKS", st.session_state.kid,
                           placeholder="6bd2d4b1-c99b-4eb2-99bc-5395e31dd6ad")
        st.session_state.kid = kid
        if not kid.strip():
            st.markdown("""
            <div style='background:#fee2e2;border-left:4px solid #ef4444;border-radius:6px;padding:0.5rem 0.8rem;font-size:0.85rem;'>
            🚨 <strong>kid is empty!</strong> You MUST set this or Epic will reject your JWT. 
            Copy it from your JWKS or use Auto-Detect below.
            </div>
            """, unsafe_allow_html=True)
    with col2:
        jwks_url = st.text_input("JWKS URL (jku)", st.session_state.jwks_url)
        st.session_state.jwks_url = jwks_url
        token_ep = st.text_input("Token Endpoint (aud)", st.session_state.token_endpoint)
        st.session_state.token_endpoint = token_ep

    # --- JWKS auto-detect ---
    st.markdown("#### 🔍 Auto-Detect from JWKS")
    st.caption("Paste your JWKS JSON below (the contents of your `.well-known/jwks.json`), and the app will auto-detect the algorithm, kid, and key type.")
    jwks_raw = st.text_area(
        "JWKS JSON (optional — for auto-detection):",
        height=150,
        placeholder='{\n  "keys": [\n    {\n      "kty": "RSA",\n      "kid": "696aeb4a-...",\n      "alg": "RS256",\n      "n": "...",\n      "e": "AQAB"\n    }\n  ]\n}',
        key="jwks_detect_input",
    )

    if jwks_raw.strip():
        try:
            jwks_data = json.loads(jwks_raw)
            keys_list = jwks_data.get("keys", [jwks_data] if "kty" in jwks_data else [])

            if keys_list:
                st.success(f"✅ Found **{len(keys_list)}** key(s) in JWKS")
                for i, k in enumerate(keys_list):
                    k_kid = k.get("kid", "—")
                    k_alg = k.get("alg", "not specified")
                    k_kty = k.get("kty", "—")
                    k_use = k.get("use", "not specified")
                    has_d = "d" in k
                    key_label = f"Key {i+1}: kid=`{k_kid}` | kty=`{k_kty}` | alg=`{k_alg}` | use=`{k_use}` | {'🔐 private' if has_d else '🔓 public'}"
                    st.markdown(f"- {key_label}")

                # Auto-fill from first key (or key with matching kid)
                target_key = keys_list[0]
                if kid:
                    matched = [k for k in keys_list if k.get("kid") == kid]
                    if matched:
                        target_key = matched[0]

                detected_alg = target_key.get("alg", "")
                detected_kid = target_key.get("kid", "")

                if detected_alg:
                    if detected_alg != alg:
                        st.warning(
                            f"⚠️ **Algorithm mismatch!** JWKS says `{detected_alg}` but you selected `{alg}`. "
                            f"This WILL cause `invalid_grant`."
                        )
                    if st.button(f"✅ Apply detected settings (alg={detected_alg}, kid={detected_kid})", key="apply_jwks"):
                        st.session_state.key_algorithm = detected_alg
                        st.session_state.kid = detected_kid
                        st.rerun()
                else:
                    st.info("No `alg` field in JWKS key. You'll need to set the algorithm manually based on the key type (`kty`).")
                    kty = target_key.get("kty", "")
                    if kty == "RSA":
                        st.markdown("Key is RSA → use **RS256**, **RS384**, or **RS512**")
                    elif kty == "EC":
                        crv = target_key.get("crv", "")
                        suggested = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}.get(crv, "ES256")
                        st.markdown(f"Key is EC (curve: {crv}) → use **{suggested}**")
            else:
                st.warning("No keys found in the JSON.")
        except json.JSONDecodeError:
            st.error("Invalid JSON — paste the full JWKS response.")

    st.markdown("### 🔐 Private Key")
    st.markdown("""
    <div class='warn-box'>
    ⚠️ <strong>Security:</strong> This key stays local in your Streamlit session.
    Never share private keys via email / Slack. If you're uncomfortable pasting here,
    use the generated JWT claims below and sign using your own tooling (openssl, jwt.io offline, etc.)
    </div>
    """, unsafe_allow_html=True)

    key_format = st.radio(
        "What format is your private key in?",
        ["PEM (-----BEGIN PRIVATE KEY-----)", "JWK JSON ({\"kty\": \"RSA\", ...})", "Raw Base64 (no headers)"],
        index=0,
        horizontal=True,
    )

    if "JWK" in key_format:
        placeholder_text = '{\n  "kty": "RSA",\n  "kid": "696aeb4a-...",\n  "n": "0vx7agoebGc...",\n  "e": "AQAB",\n  "d": "X4cTteJY_gn...",\n  "p": "...",\n  "q": "...",\n  "dp": "...",\n  "dq": "...",\n  "qi": "..."\n}'
        help_text = "Paste the **private** JWK object (must contain the `d` parameter). If you have a JWKS with a `keys` array, paste just the single key object that has the `d` field."
    elif "Raw" in key_format:
        placeholder_text = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASC..."
        help_text = "Paste the base64 key material without `-----BEGIN/END-----` headers. The app will auto-wrap it."
    else:
        placeholder_text = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg...\n-----END PRIVATE KEY-----"
        help_text = "Standard PEM format. Accepts PKCS#8 (`BEGIN PRIVATE KEY`) or PKCS#1 (`BEGIN RSA PRIVATE KEY` / `BEGIN EC PRIVATE KEY`)."

    st.caption(help_text)
    private_key_input = st.text_area(
        "Paste your private key:",
        value=st.session_state.private_key_pem,
        height=200,
        placeholder=placeholder_text,
    )
    st.session_state.private_key_pem = private_key_input

    # Show the JWT claims regardless
    now_ts = int(time.time())
    jti_val = str(uuid.uuid4())
    jwt_header = {
        "alg": alg,
        "typ": "JWT",
        "kid": kid if kid else "<your-key-id>",
        "jku": jwks_url,
    }
    jwt_payload = {
        "iss": st.session_state.client_id,
        "sub": st.session_state.client_id,
        "aud": token_ep,
        "jti": jti_val,
        "nbf": now_ts,
        "iat": now_ts,
        "exp": now_ts + 300,
    }

    # TEFCA IAS Extension in JWT
    st.markdown("---")
    st.markdown("#### 🔐 TEFCA IAS Extension in JWT Payload")
    st.markdown("""
    <div class='info-box'>
    For TEFCA IAS, the JWT payload should include an <code>extensions</code> block with the 
    CLEAR id_token and purpose of use. This tells Epic the patient has been identity-proofed.
    </div>
    """, unsafe_allow_html=True)

    include_tefca_jwt = st.checkbox("Include TEFCA IAS extensions in JWT payload", value=True, key="tefca_jwt_toggle")

    if include_tefca_jwt:
        col_e1, col_e2 = st.columns(2)
        with col_e1:
            jwt_purpose = st.text_input("Purpose of Use", "T-IAS", key="jwt_purpose")
            jwt_ial = st.selectbox("Identity Assurance Level", ["2", "1", "3"], index=0, key="jwt_ial")
            jwt_verified_by = st.text_input("Verified By (CSP)", "CLEAR", key="jwt_csp")
        with col_e2:
            jwt_id_token = st.text_area(
                "CLEAR id_token",
                value=st.session_state.get("tefca_id_token", ""),
                height=80,
                placeholder="eyJhbGciOiJSUzI1NiJ9...",
                key="jwt_tefca_token",
            )

        tefca_extension = {
            "tefca_ias": {
                "purpose_of_use": jwt_purpose,
                "user_identity": {
                    "ial": jwt_ial,
                    "verified_by": jwt_verified_by,
                },
            }
        }
        if jwt_id_token.strip():
            tefca_extension["tefca_ias"]["id_token"] = jwt_id_token.strip()

        jwt_payload["extensions"] = tefca_extension

        if not jwt_id_token.strip():
            st.markdown("""
            <div class='warn-box'>
            ⚠️ <strong>No CLEAR id_token provided in JWT.</strong>
            Epic Sandbox accepts fake/empty CSP tokens for testing.
            SIT may require a real token — get it from the Accounts Team.
            </div>
            """, unsafe_allow_html=True)

    st.markdown("### JWT Claims Preview")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("<p class='code-label'>Header</p>", unsafe_allow_html=True)
        st.json(jwt_header)
    with c2:
        st.markdown("<p class='code-label'>Payload</p>", unsafe_allow_html=True)
        st.json(jwt_payload)

    st.markdown(f"""
    <div class='info-box'>
    <strong>Timestamps (current):</strong><br>
    • <code>iat/nbf</code> = {now_ts} ({datetime.fromtimestamp(now_ts, tz=timezone.utc).isoformat()})<br>
    • <code>exp</code> = {now_ts + 300} (5 minutes from now)<br>
    • <code>jti</code> = {jti_val} (unique per request, max 151 chars)
    </div>
    """, unsafe_allow_html=True)

    # Attempt to sign if private key is provided
    if st.button("🔏 Sign JWT", type="primary"):
        if not private_key_input.strip():
            st.error("Please paste your private key above.")
        elif not kid.strip():
            st.error("""
            ❌ **`kid` (Key ID) is required!** Without it, Epic can't find the right public key 
            in your JWKS to verify the signature → `invalid_client`.
            
            **How to get it:**
            1. Open your JWKS: `https://sit2-api.cvshealth.com/public/.well-known/jwks.json`
            2. Find the key you're using
            3. Copy its `"kid"` value exactly
            4. Paste it in the **Key ID (kid)** field above
            
            Or paste the full JWKS JSON in the **Auto-Detect from JWKS** section above and click Apply.
            """)
        else:
            try:
                import jwt as pyjwt
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod, ec as ec_mod
                from cryptography.hazmat.backends import default_backend

                raw_key = private_key_input.strip()
                private_key_obj = None

                # ── FORMAT A: JWK JSON ───────────────────────────────
                if "JWK" in key_format or raw_key.lstrip().startswith("{"):
                    try:
                        jwk_data = json.loads(raw_key)

                        # Handle JWKS wrapper ({"keys": [...]})
                        if "keys" in jwk_data and isinstance(jwk_data["keys"], list):
                            # Find the key with "d" (private component)
                            priv_keys = [k for k in jwk_data["keys"] if "d" in k]
                            if not priv_keys:
                                raise ValueError(
                                    "JWKS contains only public keys (no 'd' parameter). "
                                    "You need the **private** key, not the public JWKS."
                                )
                            jwk_data = priv_keys[0]
                            st.info(f"📌 Found private key in JWKS array (kid: `{jwk_data.get('kid', 'n/a')}`)")

                        if "d" not in jwk_data:
                            raise ValueError(
                                "This JWK has no `d` parameter — it's a **public** key. "
                                "The private key JWK must include `d` (and `p`, `q`, `dp`, `dq`, `qi` for RSA)."
                            )

                        # Auto-extract kid from JWK if not set
                        if not kid and jwk_data.get("kid"):
                            kid = jwk_data["kid"]
                            st.session_state.kid = kid
                            st.info(f"📌 Auto-detected `kid` from JWK: `{kid}`")

                        kty = jwk_data.get("kty", "").upper()

                        if kty == "RSA":
                            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers

                            def _b64_to_int(val):
                                val += "=" * (4 - len(val) % 4)
                                return int.from_bytes(base64.urlsafe_b64decode(val), "big")

                            public_numbers = RSAPublicNumbers(
                                e=_b64_to_int(jwk_data["e"]),
                                n=_b64_to_int(jwk_data["n"]),
                            )
                            private_key_obj = RSAPrivateNumbers(
                                p=_b64_to_int(jwk_data["p"]),
                                q=_b64_to_int(jwk_data["q"]),
                                d=_b64_to_int(jwk_data["d"]),
                                dmp1=_b64_to_int(jwk_data["dp"]),
                                dmq1=_b64_to_int(jwk_data["dq"]),
                                iqmp=_b64_to_int(jwk_data["qi"]),
                                public_numbers=public_numbers,
                            ).private_key(default_backend())

                        elif kty == "EC":
                            from cryptography.hazmat.primitives.asymmetric.ec import (
                                EllipticCurvePrivateNumbers, EllipticCurvePublicNumbers,
                                SECP256R1, SECP384R1, SECP521R1,
                            )
                            crv_map = {
                                "P-256": SECP256R1(), "P-384": SECP384R1(), "P-521": SECP521R1(),
                            }
                            crv = crv_map.get(jwk_data.get("crv"))
                            if not crv:
                                raise ValueError(f"Unsupported EC curve: {jwk_data.get('crv')}")

                            def _b64_to_int(val):
                                val += "=" * (4 - len(val) % 4)
                                return int.from_bytes(base64.urlsafe_b64decode(val), "big")

                            public_numbers = EllipticCurvePublicNumbers(
                                x=_b64_to_int(jwk_data["x"]),
                                y=_b64_to_int(jwk_data["y"]),
                                curve=crv,
                            )
                            private_key_obj = EllipticCurvePrivateNumbers(
                                private_value=_b64_to_int(jwk_data["d"]),
                                public_numbers=public_numbers,
                            ).private_key(default_backend())

                        else:
                            raise ValueError(f"Unsupported JWK key type: {kty}")

                    except json.JSONDecodeError:
                        raise ValueError(
                            "Key looks like JSON but couldn't be parsed. "
                            "Check for trailing commas, missing quotes, or truncation."
                        )

                # ── FORMAT B: Raw Base64 (no PEM headers) ────────────
                elif "Raw" in key_format or (
                    not raw_key.startswith("-----") and not raw_key.startswith("{")
                ):
                    # Clean up whitespace and try to decode as DER
                    b64_clean = raw_key.replace("\n", "").replace("\r", "").replace(" ", "").replace("\t", "")

                    # Try wrapping as PKCS#8 PEM first
                    wrapped = "\n".join([b64_clean[i:i+64] for i in range(0, len(b64_clean), 64)])

                    for header_type in ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"]:
                        pem_candidate = f"-----BEGIN {header_type}-----\n{wrapped}\n-----END {header_type}-----"
                        try:
                            private_key_obj = serialization.load_pem_private_key(
                                pem_candidate.encode(), password=None, backend=default_backend()
                            )
                            st.info(f"📌 Key auto-wrapped as `{header_type}` PEM")
                            break
                        except Exception:
                            continue

                    if private_key_obj is None:
                        # Try raw DER
                        try:
                            der_bytes = base64.b64decode(b64_clean)
                            private_key_obj = serialization.load_der_private_key(
                                der_bytes, password=None, backend=default_backend()
                            )
                            st.info("📌 Key loaded as raw DER")
                        except Exception:
                            raise ValueError(
                                "Could not decode the raw base64 as a private key. "
                                "Make sure you pasted the complete key material."
                            )

                # ── FORMAT C: PEM ────────────────────────────────────
                else:
                    # Fix common paste issues (collapsed newlines, etc.)
                    for tag in [
                        "RSA PRIVATE KEY", "PRIVATE KEY", "EC PRIVATE KEY",
                    ]:
                        begin = f"-----BEGIN {tag}-----"
                        end   = f"-----END {tag}-----"
                        if begin in raw_key and end in raw_key:
                            header_part = raw_key[raw_key.index(begin) + len(begin):raw_key.index(end)].strip()
                            b64_clean = header_part.replace("\n", "").replace("\r", "").replace(" ", "").replace("\t", "")
                            wrapped = "\n".join([b64_clean[i:i+64] for i in range(0, len(b64_clean), 64)])
                            raw_key = f"{begin}\n{wrapped}\n{end}"
                            break

                    # Also handle \\n (literal backslash-n from JSON / Secret Manager)
                    if "\\n" in raw_key:
                        raw_key = raw_key.replace("\\n", "\n")

                    key_bytes = raw_key.encode("utf-8")
                    try:
                        private_key_obj = serialization.load_pem_private_key(
                            key_bytes, password=None, backend=default_backend()
                        )
                    except Exception as load_err:
                        # Try DER as fallback
                        try:
                            raw_b64 = raw_key
                            for rem in ["-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----",
                                        "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----",
                                        "-----BEGIN EC PRIVATE KEY-----", "-----END EC PRIVATE KEY-----"]:
                                raw_b64 = raw_b64.replace(rem, "")
                            raw_b64 = raw_b64.replace("\n", "").replace("\r", "").replace(" ", "")
                            der_bytes = base64.b64decode(raw_b64)
                            private_key_obj = serialization.load_der_private_key(
                                der_bytes, password=None, backend=default_backend()
                            )
                        except Exception:
                            raise load_err

                if private_key_obj is None:
                    raise ValueError("Could not load the key in any supported format.")

                # ── Detect key type & validate algorithm match ───────
                is_rsa = isinstance(private_key_obj, rsa_mod.RSAPrivateKey)
                is_ec  = isinstance(private_key_obj, ec_mod.EllipticCurvePrivateKey)

                rsa_algs = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}
                ec_algs  = {"ES256", "ES384", "ES512"}

                if is_rsa and alg not in rsa_algs:
                    st.warning(
                        f"⚠️ You have an **RSA** key but selected **{alg}** (EC algorithm). "
                        f"Switching to **RS384** (Epic recommended)."
                    )
                    alg = "RS384"
                    st.session_state.key_algorithm = alg
                elif is_ec and alg not in ec_algs:
                    curve_name = private_key_obj.curve.name
                    auto_alg = {
                        "secp256r1": "ES256",
                        "secp384r1": "ES384",
                        "secp521r1": "ES512",
                    }.get(curve_name, "ES256")
                    st.warning(
                        f"⚠️ You have an **EC ({curve_name})** key but selected **{alg}** (RSA algorithm). "
                        f"Switching to **{auto_alg}**."
                    )
                    alg = auto_alg
                    st.session_state.key_algorithm = alg

                # ── Re-serialize to clean PKCS8 PEM for PyJWT ────────
                clean_pem = private_key_obj.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )

                # ── Refresh timestamps so JWT is fresh ───────────────
                now_fresh = int(time.time())
                jwt_payload_fresh = {
                    **jwt_payload,
                    "nbf": now_fresh,
                    "iat": now_fresh,
                    "exp": now_fresh + 300,
                    "jti": str(uuid.uuid4()),
                }

                jwt_token = pyjwt.encode(
                    jwt_payload_fresh,
                    clean_pem,
                    algorithm=alg,
                    headers={"kid": kid, "jku": jwks_url, "typ": "JWT"},
                )
                st.session_state.jwt_generated = jwt_token
                key_type = "RSA" if is_rsa else f"EC ({private_key_obj.curve.name})" if is_ec else "Unknown"
                key_bits = private_key_obj.key_size if hasattr(private_key_obj, 'key_size') else "?"
                st.success(f"✅ JWT signed successfully!  (Key: **{key_type} {key_bits}-bit**, Algorithm: **{alg}**)")

            except Exception as e:
                st.error(f"JWT signing failed: {e}")
                st.markdown(f"""
                **Troubleshooting checklist:**

                1. **Is this actually a private key?** It must contain the secret `d` component.
                   A public key (from your JWKS endpoint) won't work for signing.

                2. **JWK format** — if your key is JSON, it must have fields like `"d"`, `"p"`, `"q"` (RSA) 
                   or `"d"`, `"x"`, `"y"` (EC). If it only has `"n"` and `"e"` — that's the public key.

                3. **Raw base64** — select "Raw Base64" format above and paste just the base64 
                   characters (no headers, no JSON wrapper).

                4. **GCP Secret Manager** — keys exported from GCP often have `\\n` as literal text. 
                   The app handles this, but double-check for extra escaping.

                5. **Key must not be encrypted** — if your PEM has `Proc-Type: 4,ENCRYPTED`, 
                   decrypt first: `openssl rsa -in encrypted.pem -out decrypted.pem`

                6. **Match key type to algorithm:**
                   - RSA key → RS256, RS384, RS512
                   - EC P-256 key → ES256
                   - EC P-384 key → ES384
                """)

    if st.session_state.jwt_generated:
        st.markdown("<p class='code-label'>Signed client_assertion JWT</p>", unsafe_allow_html=True)
        st.code(st.session_state.jwt_generated, language="text")

        # Decode and show parts
        parts = st.session_state.jwt_generated.split(".")
        if len(parts) == 3:
            st.markdown("**JWT Breakdown:**")
            for i, (label, part) in enumerate(zip(["Header", "Payload", "Signature"], parts)):
                if i < 2:
                    try:
                        padded = part + "=" * (4 - len(part) % 4)
                        decoded = json.loads(base64.urlsafe_b64decode(padded))
                        with st.expander(f"📦 {label}"):
                            st.json(decoded)
                    except Exception:
                        pass

    st.markdown("---")

    st.markdown("""
    ### ⚠️ Common Mistakes (from Epic docs)
    - `iat` and `nbf` must **NOT** be in the future
    - `exp` must be **in the future** but no more than 5 min after `iat`
    - `jti` must be max **151 characters**
    - Use `client_assertion` (underscore), **NOT** `client-assertion` (hyphen)
    - Don't double-encode the `client_assertion_type` value
    - Private key must match public key at your registered JWK Set URL
    - After uploading a new key, it can take up to **60 minutes** to sync with Sandbox
    """)

    c1, c2 = st.columns(2)
    with c1:
        if st.button("← Back", key="b4"):
            st.session_state.current_step = 3
            st.rerun()
    with c2:
        if st.button("Next → Token Exchange", type="primary", key="n4"):
            st.session_state.current_step = 5
            st.rerun()


# ===================================================================
# STEP 5 — Token Exchange
# ===================================================================
elif step == 5:
    st.markdown("## Step 5: Token Exchange")
    st.markdown("""
    <div class='info-box'>
    Exchange the <strong>auth code</strong> + <strong>signed JWT</strong> for an
    <strong>access token</strong>. This is a Postman / cURL call — NOT a browser redirect.
    </div>
    """, unsafe_allow_html=True)

    token_ep = st.text_input("Token Endpoint", st.session_state.token_endpoint)
    auth_code = st.text_input("Auth Code (from Step 3)", st.session_state.auth_code)
    redirect_uri = st.text_input("Redirect URI", st.session_state.redirect_uri, key="redir5")
    jwt_val = st.text_area("Client Assertion JWT (from Step 4)", st.session_state.jwt_generated, height=100)

    st.markdown("### Postman Setup")
    st.markdown(f"<p class='code-label'>POST Request</p>", unsafe_allow_html=True)

    postman_body = {
        "grant_type": "authorization_code",
        "code": auth_code if auth_code else "<AUTH_CODE_FROM_STEP_3>",
        "redirect_uri": redirect_uri,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": (jwt_val[:50] + "...") if jwt_val else "<JWT_FROM_STEP_4>",
    }

    st.markdown(f"""
    **URL:** `POST {token_ep}`
    
    **Headers:**
    | Key | Value |
    |-----|-------|
    | Content-Type | `application/x-www-form-urlencoded` |
    
    **Body (x-www-form-urlencoded):**
    """)

    for k, v in postman_body.items():
        st.code(f"{k} = {v}", language="text")

    # cURL equivalent
    curl_cmd = f"""curl -X POST "{token_ep}" \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "grant_type=authorization_code" \\
  -d "code={auth_code or '<AUTH_CODE>'}" \\
  -d "redirect_uri={redirect_uri}" \\
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \\
  -d "client_assertion={(jwt_val[:60] + '...') if jwt_val else '<SIGNED_JWT>'}" """

    with st.expander("📋 cURL Command"):
        st.code(curl_cmd, language="bash")

    st.markdown("### Response")
    st.markdown("Paste the token response JSON from Postman:")
    token_resp = st.text_area(
        "Token Response JSON",
        value=st.session_state.token_response_raw,
        height=180,
        placeholder='{\n  "access_token": "eyJ...",\n  "token_type": "Bearer",\n  "expires_in": 3600,\n  "patient": "eABcDeFg...",\n  "scope": "patient/*.read openid fhirUser"\n}'
    )
    st.session_state.token_response_raw = token_resp

    if token_resp.strip():
        try:
            resp = json.loads(token_resp)

            # ── Error handling ───────────────────────────────────
            if "error" in resp:
                error_code = resp.get("error", "")
                error_desc = resp.get("error_description", "No description provided")

                if error_code == "invalid_grant":
                    st.error(f"❌ **invalid_grant** — {error_desc}")

                    st.markdown("""
                    <div class='warn-box'>
                    <strong>🔍 Diagnosing <code>invalid_grant</code></strong><br><br>
                    This error means Epic rejected the authorization code or the token request parameters. 
                    Work through this checklist <strong>top to bottom</strong> — the most common cause is #1.
                    </div>
                    """, unsafe_allow_html=True)

                    st.markdown("---")
                    st.markdown("#### 🔎 Diagnostic Checklist")

                    # Cause 1: Expired auth code
                    st.markdown("""
                    **① Auth code expired (⏱ MOST COMMON)**
                    
                    The auth code from Step 3 expires in **~5 minutes**. If you spent time 
                    generating the JWT in Step 4, the code is likely dead by now.
                    
                    **Fix:** Go back to Step 2, paste the authorize URL in your browser again, 
                    log into MyChart, grab a **fresh code**, then **immediately** do the token exchange 
                    (have Postman pre-loaded and the JWT already generated).
                    """)

                    # Cause 2: Code already used
                    st.markdown("""
                    **② Auth code already used**
                    
                    Each auth code is **one-time use only**. If you already tried a token exchange 
                    with this code (even if it failed for another reason), the code is burned.
                    
                    **Fix:** Get a fresh code from Step 3.
                    """)

                    # Cause 3: redirect_uri mismatch
                    st.markdown("""
                    **③ redirect_uri mismatch**
                    
                    The `redirect_uri` in the token request must **exactly match** what was used 
                    in the authorize URL — same scheme, host, path, no trailing slash difference.
                    """)
                    col_a, col_b = st.columns(2)
                    with col_a:
                        st.markdown(f"**Authorize URL used:**")
                        st.code(st.session_state.redirect_uri, language="text")
                    with col_b:
                        st.markdown(f"**Token request using:**")
                        st.code(redirect_uri, language="text")
                    if st.session_state.redirect_uri.rstrip("/") != redirect_uri.rstrip("/"):
                        st.error("⚠️ **MISMATCH DETECTED** — these don't match!")
                    else:
                        st.success("✅ redirect_uri matches")

                    # Cause 4: JWT timing issues
                    st.markdown("""
                    **④ JWT timing issues (`iat`, `nbf`, `exp`)**
                    
                    Epic is strict about timestamps:
                    - `iat` and `nbf` must **NOT** be in the future
                    - `exp` must be in the future but **≤ 5 min** after `iat`
                    - Server clock skew can cause issues
                    """)
                    if st.session_state.jwt_generated:
                        try:
                            parts = st.session_state.jwt_generated.split(".")
                            padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                            payload_data = json.loads(base64.urlsafe_b64decode(padded))
                            jwt_iat = payload_data.get("iat", 0)
                            jwt_exp = payload_data.get("exp", 0)
                            jwt_nbf = payload_data.get("nbf", 0)
                            now_check = int(time.time())

                            c1, c2, c3, c4 = st.columns(4)
                            with c1:
                                st.metric("Current Time", now_check)
                            with c2:
                                age = now_check - jwt_iat
                                st.metric("JWT iat", jwt_iat, delta=f"{age}s ago", delta_color="inverse")
                            with c3:
                                remaining = jwt_exp - now_check
                                st.metric("JWT exp", jwt_exp, delta=f"{remaining}s left", delta_color="normal")
                            with c4:
                                st.metric("JWT nbf", jwt_nbf)

                            issues = []
                            if jwt_iat > now_check:
                                issues.append("❌ `iat` is in the FUTURE")
                            if jwt_nbf > now_check:
                                issues.append("❌ `nbf` is in the FUTURE")
                            if jwt_exp <= now_check:
                                issues.append("❌ `exp` is in the PAST — JWT has expired!")
                            if jwt_exp - jwt_iat > 300:
                                issues.append("⚠️ `exp` is more than 5 min after `iat`")

                            if issues:
                                for issue in issues:
                                    st.warning(issue)
                                st.markdown("**Fix:** Go to Step 4, click **Sign JWT** again to generate a fresh one with current timestamps.")
                            else:
                                st.success("✅ JWT timestamps look valid")
                        except Exception:
                            st.warning("Could not decode JWT to check timestamps")

                    # Cause 5: aud mismatch
                    st.markdown("""
                    **⑤ `aud` in JWT doesn't match token endpoint**
                    
                    The `aud` claim in your JWT must be the **exact** token endpoint URL.
                    """)
                    if st.session_state.jwt_generated:
                        try:
                            parts = st.session_state.jwt_generated.split(".")
                            padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                            payload_data = json.loads(base64.urlsafe_b64decode(padded))
                            jwt_aud = payload_data.get("aud", "")
                            col_a, col_b = st.columns(2)
                            with col_a:
                                st.code(f"JWT aud: {jwt_aud}", language="text")
                            with col_b:
                                st.code(f"Token EP: {token_ep}", language="text")
                            if jwt_aud == token_ep:
                                st.success("✅ `aud` matches token endpoint")
                            else:
                                st.error("⚠️ **MISMATCH** — `aud` doesn't match the token endpoint!")
                        except Exception:
                            pass

                    # Cause 6: JTI reuse
                    st.markdown("""
                    **⑥ `jti` reused**
                    
                    Epic requires a **unique** `jti` for every token request. If you're reusing 
                    the same JWT from a previous attempt, the `jti` is already burned.
                    
                    **Fix:** Go to Step 4, click **Sign JWT** again (it auto-generates a new UUID).
                    """)

                    # Cause 7: Key mismatch
                    st.markdown("""
                    **⑦ Private key doesn't match JWKS public key**
                    
                    The key you signed with must correspond to a public key at your registered 
                    JWKS URL. Also verify the `kid` in the JWT header matches a key in the JWKS.
                    """)
                    st.code(f"JWKS URL: {st.session_state.jwks_url}\nJWT kid:  {st.session_state.kid or '(not set)'}", language="text")

                    # Quick retry workflow
                    st.markdown("---")
                    st.markdown("#### 🚀 Quick Retry Workflow")
                    st.markdown("""
                    Since the most common cause is an expired/reused auth code + stale JWT:
                    
                    1. **Step 4:** Click **Sign JWT** to get a fresh JWT with new timestamps + jti
                    2. **Step 2:** Paste the authorize URL in your browser again
                    3. **Step 3:** Log into MyChart, grab the new code **fast**
                    4. **Step 5:** Immediately paste the new code + fresh JWT into Postman and fire
                    
                    💡 **Pro tip:** Have Postman already set up with everything except `code` 
                    and `client_assertion`. Generate the JWT first, paste it into Postman, 
                    THEN go get the auth code, paste it, and hit Send within seconds.
                    """)

                    col_back, col_retry = st.columns(2)
                    with col_back:
                        if st.button("← Go to Step 4 (Re-sign JWT)", key="retry_jwt"):
                            st.session_state.current_step = 4
                            st.rerun()
                    with col_retry:
                        if st.button("← Go to Step 2 (Get fresh code)", type="primary", key="retry_code"):
                            st.session_state.auth_code = ""
                            st.session_state.token_response_raw = ""
                            st.session_state.current_step = 2
                            st.rerun()

                else:
                    # Other OAuth errors
                    st.error(f"❌ **{error_code}** — {error_desc}")
                    if error_code == "invalid_client":
                        st.markdown("""
                        **`invalid_client`** means Epic doesn't recognize your client credentials. Check:
                        - `client_id` matches what's registered with Epic
                        - JWT signature verifies against a key in your JWKS
                        - Your JWKS URL is reachable from Epic's servers
                        - If you recently uploaded a new key, wait **60 minutes** for sync
                        """)
                    elif error_code == "invalid_request":
                        st.markdown("""
                        **`invalid_request`** means a required parameter is missing or malformed. Check:
                        - All required fields are present in the POST body
                        - `client_assertion_type` is exactly `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
                        - Body is `x-www-form-urlencoded` (not JSON)
                        """)

            # ── Success handling ─────────────────────────────────
            elif "access_token" in resp:
                st.session_state.access_token = resp.get("access_token", "")
                st.session_state.patient_id = resp.get("patient", "")
                st.success("✅ Token exchange successful!")

                c1, c2, c3 = st.columns(3)
                with c1:
                    st.metric("Token Type", resp.get("token_type", "—"))
                with c2:
                    exp = resp.get("expires_in", "—")
                    st.metric("Expires In", f"{exp}s" if exp != "—" else "—")
                with c3:
                    pid = st.session_state.patient_id
                    st.metric("Patient ID", (pid[:20] + "...") if len(pid) > 20 else pid or "—")

                if st.session_state.access_token:
                    with st.expander("🔑 Access Token"):
                        st.code(st.session_state.access_token, language="text")

                # Show all fields
                with st.expander("📋 Full Response"):
                    st.json(resp)
            else:
                st.warning("Response doesn't contain `access_token` or `error`. Raw response:")
                st.json(resp)

        except json.JSONDecodeError:
            st.error("Invalid JSON — paste the complete response from Postman.")

    st.markdown("---")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("← Back", key="b5"):
            st.session_state.current_step = 4
            st.rerun()
    with c2:
        if st.button("Next → Query FHIR Resources", type="primary", key="n5"):
            st.session_state.current_step = 6
            st.rerun()


# ===================================================================
# STEP 6 — Query FHIR Resources
# ===================================================================
elif step == 6:
    st.markdown("## Step 6: Query FHIR Resources")
    st.markdown("""
    <div class='info-box'>
    Use the <strong>access token</strong> as a Bearer token to query Camila's health records.
    Run these in Postman with <code>Authorization: Bearer &lt;token&gt;</code>.
    </div>
    """, unsafe_allow_html=True)

    fhir_base = st.session_state.fhir_base_url.rstrip("/")
    patient_id = st.text_input("Patient ID (from token response)", st.session_state.patient_id)
    access_token = st.text_input("Access Token", st.session_state.access_token[:40] + "..." if len(st.session_state.access_token) > 40 else st.session_state.access_token, disabled=True)

    resources = [
        ("Patient", f"Patient/{patient_id}", "Demographics, identifiers, addresses"),
        ("DocumentReference", f"DocumentReference?patient={patient_id}", "Clinical documents (C-CDA, discharge summaries)"),
        ("Condition", f"Condition?patient={patient_id}", "Diagnoses and problems"),
        ("AllergyIntolerance", f"AllergyIntolerance?patient={patient_id}", "Allergies and adverse reactions"),
        ("MedicationRequest", f"MedicationRequest?patient={patient_id}", "Prescriptions and medication orders"),
        ("Immunization", f"Immunization?patient={patient_id}", "Vaccination records"),
        ("Observation", f"Observation?patient={patient_id}&category=vital-signs", "Vital signs (BP, weight, etc.)"),
        ("Observation (Labs)", f"Observation?patient={patient_id}&category=laboratory", "Lab results"),
        ("Encounter", f"Encounter?patient={patient_id}", "Visits and encounters"),
        ("Procedure", f"Procedure?patient={patient_id}", "Surgical and clinical procedures"),
    ]

    st.markdown("### Available FHIR Queries")
    for name, path, desc in resources:
        full_url = f"{fhir_base}/{path}"
        with st.expander(f"📄 {name} — {desc}"):
            st.markdown(f"<p class='code-label'>GET Request</p>", unsafe_allow_html=True)
            st.code(f"GET {full_url}\nAuthorization: Bearer <access_token>\nAccept: application/fhir+json", language="http")

            curl = f"""curl -s "{full_url}" \\
  -H "Authorization: Bearer {st.session_state.access_token[:30] + '...' if st.session_state.access_token else '<ACCESS_TOKEN>'}" \\
  -H "Accept: application/fhir+json" | python3 -m json.tool"""
            st.code(curl, language="bash")

            # Paste results
            res_json = st.text_area(
                f"Paste {name} response:",
                value=st.session_state.fhir_results.get(name, ""),
                height=150,
                key=f"res_{name}"
            )
            if res_json.strip():
                st.session_state.fhir_results[name] = res_json
                try:
                    parsed = json.loads(res_json)
                    total = parsed.get("total", parsed.get("id", "—"))
                    rtype = parsed.get("resourceType", "—")
                    st.success(f"✅ {rtype} — {f'Total: {total}' if isinstance(total, int) else f'ID: {total}'}")
                except json.JSONDecodeError:
                    st.error("Invalid JSON")

    st.markdown("---")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("← Back", key="b6"):
            st.session_state.current_step = 5
            st.rerun()
    with c2:
        if st.button("Next → Results & Inspection", type="primary", key="n6"):
            st.session_state.current_step = 7
            st.rerun()


# ===================================================================
# STEP 7 — Results & Inspection
# ===================================================================
elif step == 7:
    st.markdown("## Step 7: Results Summary & Inspection")

    # Progress tracker
    st.markdown("### 🗺️ End-to-End Flow Status")
    checks = {
        "SMART Discovery": bool(st.session_state.authorize_endpoint and st.session_state.token_endpoint),
        "Authorize URL Built": bool(st.session_state.client_id),
        "Auth Code Captured": bool(st.session_state.auth_code),
        "JWT Generated": bool(st.session_state.jwt_generated),
        "Token Exchanged": bool(st.session_state.access_token),
        "FHIR Data Retrieved": bool(st.session_state.fhir_results),
    }

    cols = st.columns(len(checks))
    for col, (label, done) in zip(cols, checks.items()):
        with col:
            icon = "✅" if done else "⬜"
            st.markdown(f"**{icon}**\n\n{label}")

    completed = sum(checks.values())
    st.progress(completed / len(checks), text=f"{completed}/{len(checks)} steps completed")

    # Summary of collected data
    if st.session_state.fhir_results:
        st.markdown("### 📊 Retrieved FHIR Resources")
        for name, data in st.session_state.fhir_results.items():
            if data.strip():
                try:
                    parsed = json.loads(data)
                    rtype = parsed.get("resourceType", "Unknown")

                    if rtype == "Bundle":
                        total = parsed.get("total", len(parsed.get("entry", [])))
                        st.markdown(f"**{name}:** {total} record(s)")
                        if parsed.get("entry"):
                            with st.expander(f"View {name} entries"):
                                for i, entry in enumerate(parsed["entry"][:10]):
                                    resource = entry.get("resource", {})
                                    st.json(resource)
                    else:
                        st.markdown(f"**{name}:** Single resource")
                        with st.expander(f"View {name}"):
                            st.json(parsed)
                except json.JSONDecodeError:
                    st.warning(f"{name}: Invalid JSON")

    # Key configuration summary
    st.markdown("### 🔧 Configuration Summary")
    config_data = {
        "FHIR Base URL": st.session_state.fhir_base_url,
        "Client ID": st.session_state.client_id,
        "Redirect URI": st.session_state.redirect_uri,
        "JWKS URL": st.session_state.jwks_url,
        "Key Algorithm": st.session_state.key_algorithm,
        "Key ID (kid)": st.session_state.kid or "—",
        "Authorization Endpoint": st.session_state.authorize_endpoint,
        "Token Endpoint": st.session_state.token_endpoint,
        "Patient ID": st.session_state.patient_id or "—",
    }
    for label, val in config_data.items():
        st.text_input(label, val, disabled=True, key=f"summary_{label}")

    # Architecture context
    st.markdown("---")
    st.markdown("### 📐 Architecture Context (from your past discussions)")
    st.markdown("""
    **End-to-End CVS IAS Flow:**
    
    1. **CLEAR Identity Proofing** → Patient scans DL + selfie → OIDC id_token (IAL2)
       *(Accounts Team owns CLEAR integration)*
    
    2. **Patient $match via CommonWell** → CDR Team sends demographics → CommonWell broadcasts XCPD
       → Epic Nexus responds with Patient + Organization + Endpoint resources
       *(CDR Team's entire scope)*
    
    3. **Facilitated FHIR per-site** → For each matched hospital:
       SMART Discovery → OAuth Authorize (MyChart login) → Token Exchange → FHIR Queries
       *(APP Team's scope — this is what you're testing here)*
    
    **Key findings from your $match testing:**
    - Match 1: **Epic FHIR Sandbox** (Verona, WI) — full OAuth+FHIR supported ✅
    - Match 2: **Health Gorilla** (Coral Gables, FL) — different QHIN, no endpoint returned ❌
    - Both responses confirm cross-QHIN discovery is working via CommonWell
    
    **SIT Environment:**
    - JWKS URI: `sit2-api.cvshealth.com/public/.well-known/jwks.json`
    - Your existing Epic App Orchard integration uses ES256
    - Epic Nexus (TEFCA IAS) recommends RS384 — confirm with Tyler Steier
    """)

    st.markdown("---")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("← Back to FHIR Queries", key="b7"):
            st.session_state.current_step = 6
            st.rerun()
    with c2:
        if st.button("🔄 Restart from Step 1", key="restart"):
            for k, v in DEFAULTS.items():
                st.session_state[k] = v
            st.session_state.current_step = 1
            st.rerun()
