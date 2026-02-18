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

    # ══════════════════════════════════════════════════════
    # AUTOMATED TOKEN EXCHANGE WITH FULL LOGGING
    # ══════════════════════════════════════════════════════
    st.markdown("---")
    st.markdown("### 🚀 Automated Token Exchange")
    st.markdown("""
    <div class='info-box'>
    Click below to fire the token exchange <strong>directly from this app</strong>. 
    Every detail of the request and response will be logged below for debugging.
    </div>
    """, unsafe_allow_html=True)

    can_fire = token_ep and auth_code and jwt_val
    if not can_fire:
        missing = []
        if not token_ep: missing.append("Token Endpoint")
        if not auth_code: missing.append("Auth Code")
        if not jwt_val: missing.append("JWT")
        st.warning(f"⚠️ Missing: **{', '.join(missing)}** — fill these in above before firing.")

    if st.button("🔥 Fire Token Exchange", type="primary", key="fire_token", disabled=not can_fire):
        import requests as req_lib
        import traceback

        exchange_log = []
        exchange_log.append(f"{'='*80}")
        exchange_log.append(f"EPIC FHIR TOKEN EXCHANGE — FULL DEBUG LOG")
        exchange_log.append(f"Timestamp: {datetime.now().isoformat()}")
        exchange_log.append(f"Unix Time: {int(time.time())}")
        exchange_log.append(f"{'='*80}")

        # ── Request details ──────────────────────────────
        request_body = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": redirect_uri,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": jwt_val,
        }
        request_headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }

        exchange_log.append(f"\n{'─'*40}")
        exchange_log.append(f"REQUEST")
        exchange_log.append(f"{'─'*40}")
        exchange_log.append(f"Method: POST")
        exchange_log.append(f"URL:    {token_ep}")
        exchange_log.append(f"\nHeaders:")
        for k, v in request_headers.items():
            exchange_log.append(f"  {k}: {v}")
        exchange_log.append(f"\nBody Parameters:")
        for k, v in request_body.items():
            if k == "client_assertion":
                exchange_log.append(f"  {k}: {v[:80]}...({len(v)} chars)")
            elif k == "code":
                exchange_log.append(f"  {k}: {v}")
            else:
                exchange_log.append(f"  {k}: {v}")

        # ── JWT decode for inspection ────────────────────
        exchange_log.append(f"\n{'─'*40}")
        exchange_log.append(f"JWT INSPECTION")
        exchange_log.append(f"{'─'*40}")
        try:
            jwt_parts = jwt_val.split(".")
            exchange_log.append(f"JWT Parts: {len(jwt_parts)}")
            # Header
            hdr_padded = jwt_parts[0] + "=" * (4 - len(jwt_parts[0]) % 4)
            jwt_hdr = json.loads(base64.urlsafe_b64decode(hdr_padded))
            exchange_log.append(f"\nJWT Header:")
            for k, v in jwt_hdr.items():
                exchange_log.append(f"  {k}: {v}")
            # Payload
            pay_padded = jwt_parts[1] + "=" * (4 - len(jwt_parts[1]) % 4)
            jwt_pay = json.loads(base64.urlsafe_b64decode(pay_padded))
            exchange_log.append(f"\nJWT Payload:")
            now_ts = int(time.time())
            for k, v in jwt_pay.items():
                if k in ("iat", "nbf", "exp"):
                    age = now_ts - v if k != "exp" else v - now_ts
                    label = "ago" if k != "exp" else "remaining"
                    exchange_log.append(f"  {k}: {v}  ({age}s {label})")
                elif k == "extensions":
                    exchange_log.append(f"  {k}: {json.dumps(v)[:100]}...")
                else:
                    exchange_log.append(f"  {k}: {v}")
            exchange_log.append(f"\n  Current time: {now_ts}")

            # Timing checks
            if jwt_pay.get("exp", 0) <= now_ts:
                exchange_log.append(f"  ⚠️  JWT IS EXPIRED! exp={jwt_pay.get('exp')} < now={now_ts}")
            if jwt_pay.get("iat", 0) > now_ts:
                exchange_log.append(f"  ⚠️  iat IS IN THE FUTURE!")
            if jwt_pay.get("aud") != token_ep:
                exchange_log.append(f"  ⚠️  aud MISMATCH! JWT aud={jwt_pay.get('aud')} vs token_ep={token_ep}")
        except Exception as e:
            exchange_log.append(f"  Could not decode JWT: {e}")

        # ── Validate redirect_uri match ──────────────────
        exchange_log.append(f"\n{'─'*40}")
        exchange_log.append(f"VALIDATION CHECKS")
        exchange_log.append(f"{'─'*40}")
        exchange_log.append(f"redirect_uri in request: {redirect_uri}")
        exchange_log.append(f"redirect_uri in session: {st.session_state.redirect_uri}")
        if redirect_uri != st.session_state.redirect_uri:
            exchange_log.append(f"  ⚠️  REDIRECT URI MISMATCH!")
        else:
            exchange_log.append(f"  ✅ redirect_uri matches")
        exchange_log.append(f"client_id (from JWT sub): {jwt_pay.get('sub', 'N/A') if 'jwt_pay' in dir() else 'N/A'}")
        exchange_log.append(f"kid (from JWT header): {jwt_hdr.get('kid', 'N/A') if 'jwt_hdr' in dir() else 'N/A'}")
        exchange_log.append(f"jku (from JWT header): {jwt_hdr.get('jku', 'N/A') if 'jwt_hdr' in dir() else 'N/A'}")

        # ── FIRE THE REQUEST ─────────────────────────────
        exchange_log.append(f"\n{'─'*40}")
        exchange_log.append(f"SENDING REQUEST...")
        exchange_log.append(f"{'─'*40}")

        try:
            resp_obj = req_lib.post(
                token_ep,
                data=request_body,
                headers=request_headers,
                timeout=30,
            )

            exchange_log.append(f"\n{'─'*40}")
            exchange_log.append(f"RESPONSE")
            exchange_log.append(f"{'─'*40}")
            exchange_log.append(f"Status Code: {resp_obj.status_code}")
            exchange_log.append(f"Reason:      {resp_obj.reason}")
            exchange_log.append(f"Elapsed:     {resp_obj.elapsed.total_seconds():.3f}s")
            exchange_log.append(f"\nResponse Headers:")
            for k, v in resp_obj.headers.items():
                exchange_log.append(f"  {k}: {v}")
            exchange_log.append(f"\nResponse Body (raw):")
            exchange_log.append(resp_obj.text)

            # Parse response
            try:
                resp_json = resp_obj.json()
                exchange_log.append(f"\nResponse Body (parsed JSON):")
                exchange_log.append(json.dumps(resp_json, indent=2))
            except Exception:
                resp_json = None
                exchange_log.append(f"\n  Could not parse response as JSON")

            # ── Display results ──────────────────────────
            full_log = "\n".join(exchange_log)

            if resp_obj.status_code == 200 and resp_json and "access_token" in resp_json:
                st.success(f"✅ Token exchange successful! (HTTP {resp_obj.status_code}, {resp_obj.elapsed.total_seconds():.1f}s)")
                st.session_state.access_token = resp_json.get("access_token", "")
                st.session_state.patient_id = resp_json.get("patient", "")
                st.session_state.token_response_raw = json.dumps(resp_json, indent=2)

                c1, c2, c3 = st.columns(3)
                with c1:
                    st.metric("Token Type", resp_json.get("token_type", "—"))
                with c2:
                    exp = resp_json.get("expires_in", "—")
                    st.metric("Expires In", f"{exp}s" if exp != "—" else "—")
                with c3:
                    pid = st.session_state.patient_id
                    st.metric("Patient ID", (pid[:20] + "...") if len(pid) > 20 else pid or "—")

                with st.expander("🔑 Access Token"):
                    st.code(st.session_state.access_token, language="text")
                with st.expander("📋 Full Response"):
                    st.json(resp_json)

            else:
                # ERROR RESPONSE
                error_code = resp_json.get("error", f"HTTP {resp_obj.status_code}") if resp_json else f"HTTP {resp_obj.status_code}"
                error_desc = resp_json.get("error_description", resp_obj.text[:200]) if resp_json else resp_obj.text[:200]

                st.error(f"❌ **{error_code}** — {error_desc}")

                # ── Error-specific diagnostics ───────────
                if error_code == "unauthorized_client":
                    st.markdown("""
                    <div class='warn-box'>
                    <strong>🔍 Diagnosing <code>unauthorized_client</code></strong><br><br>
                    Epic does not recognize or authorize your client for this request. 
                    This is <strong>NOT</strong> a JWT signature issue — it's an app registration / configuration issue.
                    </div>
                    """, unsafe_allow_html=True)
                    st.markdown("""
                    **① App registration deleted or expired after sandbox reset**
                    
                    Epic sandbox resets every Monday. Your app may have been wiped. 
                    Check [fhir.epic.com/Developer/Apps](https://fhir.epic.com/Developer/Apps) and confirm 
                    client ID `{cid}` still exists.
                    
                    **② Client ID mismatch**
                    
                    The `sub` and `iss` claims in your JWT must exactly match your registered client ID.
                    
                    **③ Grant type not authorized**
                    
                    Your app must be registered for `authorization_code` grant type (Confidential App).
                    If it's registered as a Backend-only app, it won't support auth code flow.
                    
                    **④ JWKS URL unreachable from Epic**
                    
                    Epic must be able to fetch your JWKS at the registered URL. If it returns 
                    a 404/500 or is behind a VPN, Epic can't verify your JWT → unauthorized_client.
                    
                    **⑤ Scopes not approved**
                    
                    If you're requesting scopes that weren't approved during app registration, 
                    Epic may reject the entire request.
                    
                    **⑥ Redirect URI not registered**
                    
                    The redirect URI must be registered with the app. A mismatch can cause 
                    unauthorized_client instead of the more specific invalid_redirect error.
                    """.format(cid=st.session_state.client_id))

                    # Show diagnostics
                    st.markdown("#### 📊 Your Configuration")
                    diag_data = {
                        "Client ID (session)": st.session_state.client_id,
                        "JWT sub claim": jwt_pay.get("sub", "N/A") if "jwt_pay" in dir() else "N/A",
                        "JWT iss claim": jwt_pay.get("iss", "N/A") if "jwt_pay" in dir() else "N/A",
                        "JWT aud claim": jwt_pay.get("aud", "N/A") if "jwt_pay" in dir() else "N/A",
                        "Token Endpoint": token_ep,
                        "JWKS URL (jku)": jwt_hdr.get("jku", "N/A") if "jwt_hdr" in dir() else "N/A",
                        "kid": jwt_hdr.get("kid", "N/A") if "jwt_hdr" in dir() else "N/A",
                        "Redirect URI": redirect_uri,
                        "Scopes requested": st.session_state.get("scopes", "N/A"),
                    }
                    for label, val in diag_data.items():
                        st.code(f"{label}: {val}", language="text")

                elif error_code == "invalid_client":
                    st.markdown("""
                    <div class='warn-box'>
                    <strong>🔍 Diagnosing <code>invalid_client</code></strong><br><br>
                    Epic could not verify your client assertion JWT. This is a <strong>signature/key</strong> issue.
                    </div>
                    """, unsafe_allow_html=True)
                    st.markdown("""
                    **① JWKS key missing `alg` field** (P0 BLOCKER)
                    
                    Your key `{kid}` must have `"alg": "RS256"` in the JWKS JSON. 
                    Without it, Epic can't determine which algorithm to verify with.
                    
                    **② kid mismatch — JWT kid doesn't match any key in JWKS**
                    
                    The `kid` in your JWT header must exactly match a `kid` in your JWKS.
                    
                    **③ Private key doesn't match the public key in JWKS**
                    
                    You may have signed with a different key pair than what's published.
                    
                    **④ JWKS URL returns error or wrong content**
                    
                    Epic fetches your JWKS URL to get the public key. If it returns HTML, 
                    a 404, or is rate-limited, verification fails silently.
                    
                    **⑤ Epic JWKS cache is stale**
                    
                    After updating your JWKS, wait up to 60 minutes for Epic to re-fetch.
                    """.format(kid=st.session_state.kid))

                elif error_code == "invalid_grant":
                    st.markdown("""
                    <div class='warn-box'>
                    <strong>🔍 Diagnosing <code>invalid_grant</code></strong><br><br>
                    The auth code is expired, already used, or there's a parameter mismatch.
                    </div>
                    """, unsafe_allow_html=True)
                    st.markdown("""
                    **Most common:** Auth code expired (5-min window) or was already used.
                    
                    **Fix:** Go back to Step 2, get a fresh auth code, and fire immediately.
                    """)

                elif error_code == "invalid_request":
                    st.markdown("""
                    **`invalid_request`** — a required parameter is missing or malformed. Check:
                    - `client_assertion_type` is exactly `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
                    - Body is `x-www-form-urlencoded` (not JSON)
                    - All required fields present
                    """)

            # ── ALWAYS show full debug log ───────────────
            with st.expander("📜 FULL DEBUG LOG (copy this for troubleshooting)", expanded=True if resp_obj.status_code != 200 else False):
                st.code(full_log, language="text")

            # ── Download log button ──────────────────────
            st.download_button(
                label="💾 Download Debug Log",
                data=full_log,
                file_name=f"epic_token_exchange_{int(time.time())}.log",
                mime="text/plain",
                key="dl_log"
            )

        except req_lib.exceptions.ConnectionError as e:
            exchange_log.append(f"\n❌ CONNECTION ERROR: {e}")
            exchange_log.append(f"\nThis usually means:")
            exchange_log.append(f"  - Token endpoint URL is wrong")
            exchange_log.append(f"  - Network/firewall is blocking the request")
            exchange_log.append(f"  - Epic server is down")
            full_log = "\n".join(exchange_log)
            st.error(f"❌ Connection failed: {e}")
            st.code(full_log, language="text")
        except req_lib.exceptions.Timeout:
            exchange_log.append(f"\n❌ TIMEOUT after 30s")
            full_log = "\n".join(exchange_log)
            st.error("❌ Request timed out after 30 seconds")
            st.code(full_log, language="text")
        except Exception as e:
            exchange_log.append(f"\n❌ UNEXPECTED ERROR: {e}")
            exchange_log.append(traceback.format_exc())
            full_log = "\n".join(exchange_log)
            st.error(f"❌ Unexpected error: {e}")
            st.code(full_log, language="text")

    # ══════════════════════════════════════════════════════
    # MANUAL FALLBACK — paste from Postman
    # ══════════════════════════════════════════════════════
    with st.expander("📋 Manual: Paste Token Response from Postman"):
        token_resp = st.text_area(
            "Token Response JSON",
            value=st.session_state.token_response_raw,
            height=180,
            placeholder='{\n  "access_token": "eyJ...",\n  "token_type": "Bearer",\n  "expires_in": 3600,\n  "patient": "eABcDeFg...",\n  "scope": "patient/*.read openid fhirUser"\n}',
            key="manual_token_resp"
        )
        st.session_state.token_response_raw = token_resp

    if token_resp.strip():
        try:
            resp = json.loads(token_resp)
            if "access_token" in resp:
                st.session_state.access_token = resp.get("access_token", "")
                st.session_state.patient_id = resp.get("patient", "")
                st.success("✅ Access token extracted from pasted response!")
                with st.expander("📋 Full Response"):
                    st.json(resp)
            elif "error" in resp:
                st.error(f"❌ **{resp.get('error')}** — {resp.get('error_description', 'No description')}")
                st.info("💡 Use the **Fire Token Exchange** button above for full diagnostics.")
            else:
                st.warning("Response doesn't contain `access_token` or `error`.")
                st.json(resp)
        except json.JSONDecodeError:
            st.error("Invalid JSON — paste the complete response.")

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
    Use the <strong>access token</strong> to query Camila's health records.
    Click <strong>🔥 Fire All Queries</strong> to run them directly from this app with full logging.
    </div>
    """, unsafe_allow_html=True)

    fhir_base = st.session_state.fhir_base_url.rstrip("/")
    patient_id = st.text_input("Patient ID (from token response)", st.session_state.patient_id)
    st.session_state.patient_id = patient_id
    access_token_display = st.session_state.access_token[:40] + "..." if len(st.session_state.access_token) > 40 else st.session_state.access_token
    st.text_input("Access Token", access_token_display, disabled=True)

    if not st.session_state.access_token:
        st.warning("⚠️ No access token — go back to Step 5 and complete the token exchange first.")
    if not patient_id:
        st.warning("⚠️ No Patient ID — this should have been returned in the token response.")

    resources = [
        ("Patient", f"Patient/{patient_id}", "Demographics, identifiers, addresses"),
        ("Condition", f"Condition?patient={patient_id}", "Diagnoses and problems"),
        ("AllergyIntolerance", f"AllergyIntolerance?patient={patient_id}", "Allergies and adverse reactions"),
        ("MedicationRequest", f"MedicationRequest?patient={patient_id}", "Prescriptions and medication orders"),
        ("Immunization", f"Immunization?patient={patient_id}", "Vaccination records"),
        ("Observation (Vitals)", f"Observation?patient={patient_id}&category=vital-signs", "Vital signs (BP, weight, etc.)"),
        ("Observation (Labs)", f"Observation?patient={patient_id}&category=laboratory", "Lab results"),
        ("DocumentReference", f"DocumentReference?patient={patient_id}", "Clinical documents (C-CDA, discharge summaries)"),
        ("Encounter", f"Encounter?patient={patient_id}", "Visits and encounters"),
        ("Procedure", f"Procedure?patient={patient_id}", "Surgical and clinical procedures"),
    ]

    # ── Resource picker ──────────────────────────────────
    st.markdown("### Select Resources to Query")
    select_all = st.checkbox("Select All", value=True, key="select_all_res")
    selected_resources = []
    cols_per_row = 5
    for row_start in range(0, len(resources), cols_per_row):
        cols = st.columns(cols_per_row)
        for i, col in enumerate(cols):
            idx = row_start + i
            if idx < len(resources):
                name, path, desc = resources[idx]
                with col:
                    if st.checkbox(name.replace(" (Vitals)", "").replace(" (Labs)", " Labs"), value=select_all, key=f"sel_{name}"):
                        selected_resources.append((name, path, desc))

    # ══════════════════════════════════════════════════════
    # AUTOMATED FHIR QUERYING
    # ══════════════════════════════════════════════════════
    st.markdown("---")
    can_query = st.session_state.access_token and patient_id and fhir_base and selected_resources
    
    if st.button("🔥 Fire All FHIR Queries", type="primary", key="fire_fhir", disabled=not can_query):
        import requests as req_lib

        query_log = []
        query_log.append(f"{'='*80}")
        query_log.append(f"EPIC FHIR RESOURCE QUERIES — FULL DEBUG LOG")
        query_log.append(f"Timestamp: {datetime.now().isoformat()}")
        query_log.append(f"FHIR Base: {fhir_base}")
        query_log.append(f"Patient ID: {patient_id}")
        query_log.append(f"Resources: {len(selected_resources)}")
        query_log.append(f"{'='*80}")

        headers = {
            "Authorization": f"Bearer {st.session_state.access_token}",
            "Accept": "application/fhir+json",
        }

        progress_bar = st.progress(0, text="Querying FHIR resources...")
        results_container = st.container()
        success_count = 0
        error_count = 0
        total_records = 0

        for i, (name, path, desc) in enumerate(selected_resources):
            full_url = f"{fhir_base}/{path}"
            progress_bar.progress((i + 1) / len(selected_resources), text=f"Querying {name}...")

            query_log.append(f"\n{'─'*60}")
            query_log.append(f"RESOURCE: {name}")
            query_log.append(f"{'─'*60}")
            query_log.append(f"URL: GET {full_url}")
            query_log.append(f"Headers:")
            query_log.append(f"  Authorization: Bearer {st.session_state.access_token[:30]}...")
            query_log.append(f"  Accept: application/fhir+json")

            try:
                resp = req_lib.get(full_url, headers=headers, timeout=30)

                query_log.append(f"\nStatus: {resp.status_code} {resp.reason}")
                query_log.append(f"Elapsed: {resp.elapsed.total_seconds():.3f}s")
                query_log.append(f"Content-Type: {resp.headers.get('Content-Type', 'N/A')}")
                query_log.append(f"Content-Length: {resp.headers.get('Content-Length', len(resp.text))}")

                # Log key response headers
                for hdr in ["X-Request-Id", "X-Correlation-Id", "WWW-Authenticate", "ETag"]:
                    if hdr in resp.headers:
                        query_log.append(f"{hdr}: {resp.headers[hdr]}")

                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        rtype = data.get("resourceType", "Unknown")

                        if rtype == "Bundle":
                            entry_count = len(data.get("entry", []))
                            total_field = data.get("total", entry_count)
                            query_log.append(f"ResourceType: Bundle")
                            query_log.append(f"Total: {total_field}")
                            query_log.append(f"Entries in page: {entry_count}")

                            st.session_state.fhir_results[name] = json.dumps(data, indent=2)
                            total_records += total_field if isinstance(total_field, int) else entry_count

                            with results_container:
                                if entry_count > 0:
                                    st.success(f"✅ **{name}** — {total_field} record(s) ({resp.elapsed.total_seconds():.1f}s)")
                                    with st.expander(f"📄 {name} — {total_field} records", expanded=False):
                                        # Summary table for key resources
                                        if name == "Condition" and data.get("entry"):
                                            conditions = []
                                            for entry in data["entry"][:20]:
                                                r = entry.get("resource", {})
                                                code = r.get("code", {})
                                                coding = code.get("coding", [{}])[0] if code.get("coding") else {}
                                                conditions.append({
                                                    "Condition": code.get("text", coding.get("display", "—")),
                                                    "Code": coding.get("code", "—"),
                                                    "System": coding.get("system", "—").split("/")[-1],
                                                    "Status": r.get("clinicalStatus", {}).get("coding", [{}])[0].get("code", "—") if r.get("clinicalStatus") else "—",
                                                    "Onset": str(r.get("onsetDateTime", r.get("onsetPeriod", {}).get("start", "—")))[:10],
                                                })
                                            st.dataframe(conditions, use_container_width=True)

                                        elif name == "MedicationRequest" and data.get("entry"):
                                            meds = []
                                            for entry in data["entry"][:20]:
                                                r = entry.get("resource", {})
                                                med = r.get("medicationCodeableConcept", r.get("medicationReference", {}))
                                                if isinstance(med, dict):
                                                    med_name = med.get("text", med.get("display", "—"))
                                                    coding = med.get("coding", [{}])[0] if med.get("coding") else {}
                                                else:
                                                    med_name = str(med)
                                                    coding = {}
                                                meds.append({
                                                    "Medication": med_name,
                                                    "Status": r.get("status", "—"),
                                                    "Intent": r.get("intent", "—"),
                                                    "Authored": str(r.get("authoredOn", "—"))[:10],
                                                })
                                            st.dataframe(meds, use_container_width=True)

                                        elif name == "AllergyIntolerance" and data.get("entry"):
                                            allergies = []
                                            for entry in data["entry"][:20]:
                                                r = entry.get("resource", {})
                                                code = r.get("code", {})
                                                coding = code.get("coding", [{}])[0] if code.get("coding") else {}
                                                allergies.append({
                                                    "Allergen": code.get("text", coding.get("display", "—")),
                                                    "Type": r.get("type", "—"),
                                                    "Category": ", ".join(r.get("category", ["—"])),
                                                    "Criticality": r.get("criticality", "—"),
                                                    "Status": r.get("clinicalStatus", {}).get("coding", [{}])[0].get("code", "—") if r.get("clinicalStatus") else "—",
                                                })
                                            st.dataframe(allergies, use_container_width=True)

                                        elif name == "Immunization" and data.get("entry"):
                                            immunizations = []
                                            for entry in data["entry"][:20]:
                                                r = entry.get("resource", {})
                                                vaccine = r.get("vaccineCode", {})
                                                coding = vaccine.get("coding", [{}])[0] if vaccine.get("coding") else {}
                                                immunizations.append({
                                                    "Vaccine": vaccine.get("text", coding.get("display", "—")),
                                                    "Date": str(r.get("occurrenceDateTime", "—"))[:10],
                                                    "Status": r.get("status", "—"),
                                                })
                                            st.dataframe(immunizations, use_container_width=True)

                                        else:
                                            # Generic: show first 5 entries as JSON
                                            for j, entry in enumerate(data["entry"][:5]):
                                                st.json(entry.get("resource", entry))
                                            if entry_count > 5:
                                                st.caption(f"... and {entry_count - 5} more entries")

                                    success_count += 1
                                else:
                                    st.info(f"ℹ️ **{name}** — 0 records returned ({resp.elapsed.total_seconds():.1f}s)")
                                    success_count += 1

                        elif rtype == "Patient":
                            query_log.append(f"ResourceType: Patient")
                            query_log.append(f"Patient ID: {data.get('id', 'N/A')}")
                            st.session_state.fhir_results[name] = json.dumps(data, indent=2)
                            total_records += 1
                            success_count += 1

                            with results_container:
                                st.success(f"✅ **{name}** — found ({resp.elapsed.total_seconds():.1f}s)")
                                with st.expander(f"👤 {name} — Demographics", expanded=False):
                                    p_name = data.get("name", [{}])[0]
                                    given = " ".join(p_name.get("given", []))
                                    family = p_name.get("family", "")
                                    dob = data.get("birthDate", "—")
                                    gender = data.get("gender", "—")
                                    st.markdown(f"**Name:** {given} {family}")
                                    st.markdown(f"**DOB:** {dob}  |  **Gender:** {gender}")
                                    if data.get("address"):
                                        addr = data["address"][0]
                                        st.markdown(f"**Address:** {', '.join(addr.get('line', []))} {addr.get('city', '')}, {addr.get('state', '')} {addr.get('postalCode', '')}")
                                    if data.get("telecom"):
                                        for t in data["telecom"][:3]:
                                            st.markdown(f"**{t.get('system', '')}:** {t.get('value', '')}")
                                    st.json(data)

                        elif rtype == "OperationOutcome":
                            issues = data.get("issue", [])
                            severity = issues[0].get("severity", "error") if issues else "error"
                            diag = issues[0].get("diagnostics", "No details") if issues else "No details"
                            query_log.append(f"ResourceType: OperationOutcome")
                            query_log.append(f"Severity: {severity}")
                            query_log.append(f"Diagnostics: {diag}")

                            with results_container:
                                if severity in ("error", "fatal"):
                                    st.error(f"❌ **{name}** — OperationOutcome: {diag[:100]}")
                                    error_count += 1
                                else:
                                    st.warning(f"⚠️ **{name}** — OperationOutcome ({severity}): {diag[:100]}")
                                    success_count += 1
                                with st.expander(f"OperationOutcome for {name}"):
                                    st.json(data)
                        else:
                            st.session_state.fhir_results[name] = json.dumps(data, indent=2)
                            success_count += 1
                            with results_container:
                                st.success(f"✅ **{name}** — {rtype} ({resp.elapsed.total_seconds():.1f}s)")
                                with st.expander(f"View {name}"):
                                    st.json(data)

                    except json.JSONDecodeError:
                        query_log.append(f"Response is NOT JSON:")
                        query_log.append(resp.text[:500])
                        with results_container:
                            st.error(f"❌ **{name}** — Response is not JSON")
                            with st.expander(f"Raw response for {name}"):
                                st.code(resp.text[:1000], language="text")
                        error_count += 1

                elif resp.status_code == 401:
                    query_log.append(f"⚠️ 401 UNAUTHORIZED")
                    query_log.append(f"WWW-Authenticate: {resp.headers.get('WWW-Authenticate', 'N/A')}")
                    query_log.append(f"Body: {resp.text[:500]}")
                    with results_container:
                        st.error(f"❌ **{name}** — 401 Unauthorized (token may be expired or invalid)")
                        www_auth = resp.headers.get("WWW-Authenticate", "")
                        if www_auth:
                            st.code(f"WWW-Authenticate: {www_auth}", language="text")
                    error_count += 1

                elif resp.status_code == 403:
                    query_log.append(f"⚠️ 403 FORBIDDEN — scope may not include this resource")
                    query_log.append(f"Body: {resp.text[:500]}")
                    with results_container:
                        st.warning(f"⚠️ **{name}** — 403 Forbidden (scope may not cover this resource)")
                    error_count += 1

                elif resp.status_code == 404:
                    query_log.append(f"ℹ️ 404 NOT FOUND — resource or patient not found")
                    with results_container:
                        st.info(f"ℹ️ **{name}** — 404 Not Found")
                    success_count += 1

                else:
                    query_log.append(f"⚠️ HTTP {resp.status_code}")
                    query_log.append(f"Body: {resp.text[:500]}")
                    with results_container:
                        st.error(f"❌ **{name}** — HTTP {resp.status_code}: {resp.text[:200]}")
                    error_count += 1

            except Exception as e:
                query_log.append(f"❌ EXCEPTION: {e}")
                with results_container:
                    st.error(f"❌ **{name}** — {e}")
                error_count += 1

        # ── Summary ──────────────────────────────────────
        progress_bar.progress(1.0, text="Done!")

        query_log.append(f"\n{'='*60}")
        query_log.append(f"SUMMARY")
        query_log.append(f"{'='*60}")
        query_log.append(f"Successful: {success_count}")
        query_log.append(f"Errors: {error_count}")
        query_log.append(f"Total Records: {total_records}")

        st.markdown("---")
        st.markdown("### 📊 Query Summary")
        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("Successful", success_count, delta_color="normal")
        with c2:
            st.metric("Errors", error_count, delta_color="inverse")
        with c3:
            st.metric("Total Records", total_records)

        if error_count > 0 and success_count == 0:
            st.error("❌ All queries failed. Check if the access token is still valid (tokens expire in ~60 min).")
            st.markdown("**Common causes:**")
            st.markdown("- Access token expired → go back to Step 5 and get a new one")
            st.markdown("- Patient ID is wrong → check the token response from Step 5")
            st.markdown("- FHIR Base URL is wrong → verify from SMART discovery in Step 1")

        full_log = "\n".join(query_log)
        with st.expander("📜 FULL FHIR QUERY LOG", expanded=error_count > 0):
            st.code(full_log, language="text")

        st.download_button(
            label="💾 Download FHIR Query Log",
            data=full_log,
            file_name=f"epic_fhir_queries_{int(time.time())}.log",
            mime="text/plain",
            key="dl_fhir_log"
        )

    # ── Manual fallback ──────────────────────────────────
    with st.expander("📋 Manual: cURL commands + paste responses"):
        for name, path, desc in resources:
            full_url = f"{fhir_base}/{path}"
            st.markdown(f"**{name}** — {desc}")
            curl = f'curl -s "{full_url}" -H "Authorization: Bearer {st.session_state.access_token[:30]}..." -H "Accept: application/fhir+json"'
            st.code(curl, language="bash")
            res_json = st.text_area(
                f"Paste {name} response:",
                value=st.session_state.fhir_results.get(name, ""),
                height=100,
                key=f"manual_res_{name}"
            )
            if res_json.strip():
                st.session_state.fhir_results[name] = res_json

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
