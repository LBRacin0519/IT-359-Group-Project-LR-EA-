import streamlit as st
from scanners.url_scanner import scan_url
from scanners.qr_scanner import decode_qr

st.set_page_config(
    page_title="Sn00py Bl0ck3r",
    layout="wide"
)

st.title("Sn00py Bl0ck3r")
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
    st.header("QR Code Security Analysis")

    qr_file = st.file_uploader(
        "Upload a QR code image",
        type=["png", "jpg", "jpeg"],
        key="qr_upload"
    )

    if qr_file is not None:
        st.image(qr_file, caption="Uploaded QR Code", width=250)

        if st.button("Scan QR Code"):
            qr_result = decode_qr(qr_file.getvalue())

            if not qr_result["success"]:
                st.error(qr_result["error"])
            else:
                content = qr_result["content"]

                st.success("QR code decoded successfully!")
                st.write("**Decoded Content:**")
                st.code(content)

                if content.lower().startswith(("http://", "https://")):
                    result = scan_url(content)

                    if result["risk"] == "Invalid":
                        st.error(
                            "Decoded URL is invalid: "
                            + "; ".join(result["findings"])
                        )
                    else:
                        st.subheader("URL Security Results")

                        col1, col2 = st.columns(2)

                        with col1:
                            st.metric(
                                "Risk Score",
                                f"{result['score']}/100"
                            )

                        with col2:
                            st.metric("Risk Level", result["risk"])

                        st.progress(result["score"] / 100)

                        st.subheader("Security Findings")

                        for finding in result["findings"]:
                            st.write(f"• {finding}")

                        if result["risk"] in ["High", "Critical"]:
                            st.error(
                                "This QR code contains a URL with "
                                "suspicious characteristics."
                            )
                        elif result["risk"] == "Medium":
                            st.warning(
                                "Some suspicious URL characteristics "
                                "were detected."
                            )
                        else:
                            st.success(
                                "No major suspicious characteristics "
                                "detected by the current rules."
                            )
                else:
                    st.info(
                        "This QR code does not contain a supported "
                        "HTTP or HTTPS URL."
                    )

with tab3:
    st.header("Email Phishing Analysis")
    st.text_area("Paste suspicious email content here:")

with tab4:
    st.header("File Security Analysis")
    st.file_uploader("Upload a file for static analysis")
