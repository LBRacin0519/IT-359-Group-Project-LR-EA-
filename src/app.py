import streamlit as st
from scanners.url_scanner import scan_url
from scanners.email_scanner import scan_email

st.set_page_config(
    page_title="Sn00py Bl0ck3r",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Sn00py Bl0ck3r")
st.subheader("AI-Assisted Cybersecurity Threat Analyzer")

st.write(
    "Analyze suspicious URLs, QR codes, emails, and files "
    "to identify potential security threats."
)

st.warning(
    "Security assessments are advisory and do not guarantee "
    "that content is safe or malicious."
)

tab1, tab2, tab3, tab4 = st.tabs([
    "URL Scanner",
    "QR Code Scanner",
    "Email Scanner",
    "File Scanner"
])

with tab1:
    st.header("URL Security Analysis")

    url = st.text_input(
        "Enter a URL to analyze:",
        placeholder="https://example.com"
    )

    if st.button("Scan URL"):
        if not url.strip():
            st.warning("Please enter a URL.")
        else:
            result = scan_url(url)

            if result["risk"] == "Invalid":
                st.error("Invalid URL: " + "; ".join(result["findings"]))
            else:
                st.subheader("Scan Results")

                col1, col2 = st.columns(2)

                with col1:
                    st.metric("Risk Score", f"{result['score']}/100")

                with col2:
                    st.metric("Risk Level", result["risk"])

                st.progress(result["score"] / 100)

                st.subheader("Security Findings")

                for finding in result["findings"]:
                    st.write(f"• {finding}")

                if result["risk"] in ["High", "Critical"]:
                    st.error(
                        "This URL has multiple suspicious characteristics. "
                        "Exercise caution before interacting with it."
                    )
                elif result["risk"] == "Medium":
                    st.warning(
                        "Some suspicious characteristics were detected."
                    )
                else:
                    st.success(
                        "No major suspicious characteristics detected "
                        "by the current rules."
                    )

with tab2:
    st.header("QR Code Analysis")
    st.file_uploader("Upload a QR code image", type=["png", "jpg", "jpeg"])

with tab3:
    st.header("Email Phishing Analysis")

    st.caption(
        "Basic text checks only. Email headers, links, and attachments "
        "are not analyzed yet. Low risk does not mean an email is safe."
    )

    email_content = st.text_area(
        "Paste email content here:",
        height=250,
    )

    if st.button("Scan Email"):
        result = scan_email(email_content)

        if result["risk"] == "Invalid":
            st.warning(result["findings"][0])
        else:
            col1, col2 = st.columns(2)

            with col1:
                st.metric("Risk Score", f"{result['score']}/100")

            with col2:
                st.metric("Risk Level", result["risk"])

            st.progress(result["score"] / 100)

            st.subheader("Security Findings")
            for finding in result["findings"]:
                st.write(f"• {finding}")

            st.info(
                "These findings require context. Legitimate emails can "
                "trigger rules, and phishing emails can evade them."
            )

with tab4:
    st.header("File Security Analysis")
    st.file_uploader("Upload a file for static analysis")