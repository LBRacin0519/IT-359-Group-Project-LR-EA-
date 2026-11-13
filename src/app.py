import streamlit as st
from scanners.url_scanner import scan_url
from scanners.email_scanner import scan_email
from scanners.qr_scanner import decode_qr
from core.ai_analyzer import analyze_with_ai

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

    # Initialize session state to preserve scan results
    if "url_scan_result" not in st.session_state:
        st.session_state.url_scan_result = None

    if "url_ai_result" not in st.session_state:
        st.session_state.url_ai_result = None

    if "url_scanned_input" not in st.session_state:
        st.session_state.url_scanned_input = None

    # Run the original URL scanner
    if st.button("Scan URL"):
        st.session_state.url_ai_result = None
        st.session_state.url_scan_result = None
        st.session_state.url_scanned_input = None

        if not url.strip():
            st.warning("Please enter a URL.")
        else:
            result = scan_url(url)

            st.session_state.url_scan_result = result
            st.session_state.url_scanned_input = url

    # Retrieve previous scan results
    result = st.session_state.url_scan_result

    # Only display results for the currently entered URL
    if result is not None and url == st.session_state.url_scanned_input:

        if result["risk"] == "Invalid":
            st.error(
                "Invalid URL: " + "; ".join(result["findings"])
            )

        else:
            st.subheader("Scan Results")

            col1, col2 = st.columns(2)

            with col1:
                st.metric(
                    "Risk Score",
                    f"{result['score']}/100"
                )

            with col2:
                st.metric(
                    "Risk Level",
                    result["risk"]
                )

            st.progress(result["score"] / 100)

            st.subheader("Security Findings")

            for finding in result["findings"]:
                st.write(f"- {finding}")

            # Display the original security assessment
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

            # ------------------------------------------
            # SUSHI AI SECURITY EXPLANATION
            # ------------------------------------------

            st.divider()

            st.subheader("AI Security Explanation")

            st.write(
                "Generate an explanation of the detected "
                "security indicators and recommended precautions."
            )

            if st.button(
                "Generate AI Explanation",
                key="url_ai"
            ):
                with st.spinner("Generating security explanation..."):

                    ai_result = analyze_with_ai(
                        scan_type="URL",
                        score=result["score"],
                        risk=result["risk"],
                        findings=result["findings"]
                    )

                    # Store AI result to survive Streamlit reruns
                    st.session_state.url_ai_result = ai_result

            # Display AI response
            ai_result = st.session_state.url_ai_result

            if ai_result is not None:

                if ai_result["success"]:

                    if ai_result["explanation"].startswith(
                        "[OFFLINE TEST"
                    ):
                        st.info(
                            "Offline demonstration mode is active. "
                            "This explanation was not generated "
                            "by Sushi AI."
                        )

                    st.markdown(
                        ai_result["explanation"]
                    )

                else:
                    st.warning(
                        ai_result["error"]
                    )

            st.caption(
                "AI explanations are advisory. "
                "The original security scanner determines "
                "the risk score and classification."
            )


with tab2:
    st.header("QR Code Security Analysis")

    qr_file = st.file_uploader(
        "Upload a QR code image",
        type=["png", "jpg", "jpeg"],
        key="qr_upload"
    )

    if "qr_scan_result" not in st.session_state:
        st.session_state.qr_scan_result = None

    if "qr_decoded_content" not in st.session_state:
        st.session_state.qr_decoded_content = None

    if "qr_ai_result" not in st.session_state:
        st.session_state.qr_ai_result = None

    if qr_file is not None:
        st.image(
            qr_file,
            caption="Uploaded QR Code",
            width=250
        )

        if st.button("Scan QR Code"):
            st.session_state.qr_scan_result = None
            st.session_state.qr_decoded_content = None
            st.session_state.qr_ai_result = None

            qr_result = decode_qr(qr_file.getvalue())

            if not qr_result["success"]:
                st.error(qr_result["error"])
            else:
                content = qr_result["content"]

                st.session_state.qr_decoded_content = content

                if content.lower().startswith(("http://", "https://")):
                    result = scan_url(content)
                    st.session_state.qr_scan_result = result

                else:
                    st.info(
                        "This QR code does not contain "
                        "a supported HTTP or HTTPS URL."
                    )

        content = st.session_state.qr_decoded_content
        result = st.session_state.qr_scan_result

        if content is not None:
            st.success("QR code decoded successfully!")
            st.write("**Decoded Content:**")
            st.code(content)

        if result is not None:
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
                    st.metric(
                        "Risk Level",
                        result["risk"]
                    )

                st.progress(result["score"] / 100)

                st.subheader("Security Findings")

                for finding in result["findings"]:
                    st.write(f"- {finding}")

                if result["risk"] in ["High", "Critical"]:
                    st.error(
                        "This QR code contains a URL "
                        "with suspicious characteristics."
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

                # -------------------------------------
                # SUSHI AI SECURITY EXPLANATION
                # -------------------------------------

                st.divider()
                st.subheader("AI Security Explanation")

                st.write(
                    "Generate an explanation of the "
                    "security indicators found in this QR code."
                )

                if st.button(
                    "Generate QR AI Explanation",
                    key="qr_ai"
                ):
                    with st.spinner(
                        "Generating security explanation..."
                    ):
                        ai_result = analyze_with_ai(
                            scan_type="QR Code",
                            score=result["score"],
                            risk=result["risk"],
                            findings=result["findings"]
                        )

                        st.session_state.qr_ai_result = ai_result

                ai_result = st.session_state.qr_ai_result

                if ai_result is not None:
                    if ai_result["success"]:
                        if ai_result["explanation"].startswith(
                            "[OFFLINE TEST"
                        ):
                            st.info(
                                "Offline demonstration mode is active. "
                                "This explanation was not generated "
                                "by Sushi AI."
                            )

                        st.markdown(ai_result["explanation"])

                    else:
                        st.warning(ai_result["error"])

                st.caption(
                    "AI explanations are advisory. "
                    "The original scanner determines "
                    "the risk score and classification."
                )

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
                st.write(f"- {finding}")

            st.info(
                "These findings require context. Legitimate emails can "
                "trigger rules, and phishing emails can evade them."
            )

with tab4:
    st.header("File Security Analysis")
    st.file_uploader("Upload a file for static analysis")
