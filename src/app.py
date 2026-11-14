import hashlib

import streamlit as st
from scanners.url_scanner import scan_url
from scanners.email_scanner import scan_email
from scanners.file_scanner import MAX_FILE_SIZE, scan_file
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
        "Checks phishing language, pasted headers, and embedded HTTP(S) URLs. "
        "Links are never opened; low risk does not mean safe."
    )
    email_content = st.text_area(
        "Paste email content here:", height=250, key="email_text"
    )

    for state_key in ("email_scan_result", "email_ai_result", "email_scanned_input"):
        if state_key not in st.session_state:
            st.session_state[state_key] = None

    if st.button("Scan Email", key="scan_email"):
        st.session_state.email_scan_result = scan_email(email_content)
        st.session_state.email_scanned_input = email_content
        st.session_state.email_ai_result = None

    result = st.session_state.email_scan_result
    if result is not None and email_content == st.session_state.email_scanned_input:
        if result["risk"] == "Invalid":
            st.warning("; ".join(result["findings"]))
        else:
            c1, c2 = st.columns(2)
            c1.metric("Risk Score", f"{result['score']}/100")
            c2.metric("Risk Level", result["risk"])
            st.progress(result["score"] / 100)
            st.subheader("Security Findings")
            for finding in result["findings"]:
                st.write(f"- {finding}")
            st.info(
                "These rules may miss phishing attempts or flag legitimate messages."
            )

            st.divider()
            st.subheader("Email AI Security Explanation")
            if st.button("Generate Email AI Explanation", key="email_ai"):
                with st.spinner("Generating email explanation..."):
                    st.session_state.email_ai_result = analyze_with_ai(
                        scan_type="Email", score=result["score"],
                        risk=result["risk"], findings=result["findings"]
                    )
            ai_result = st.session_state.email_ai_result
            if ai_result is not None:
                if ai_result["success"]:
                    if ai_result["explanation"].startswith("[OFFLINE TEST"):
                        st.info("Offline demonstration mode: not a live Sushi AI result.")
                    st.markdown(ai_result["explanation"])
                else:
                    st.warning(ai_result["error"])
            st.caption(
                "Sushi AI explains scanner findings but cannot change the score. "
                "Only rule findings, not the original email text, are sent to Sushi AI."
            )

with tab4:
    st.header("File Security Analysis")
    st.caption(
        "Static checks only: no execution, archive unpacking, or upload of "
        "file bytes to Sushi AI. Maximum file size: 15 MiB."
    )
    file_upload = st.file_uploader(
        "Upload a file for static analysis", key="file_upload"
    )

    for state_key in ("file_scan_result", "file_ai_result", "file_scanned_id"):
        if state_key not in st.session_state:
            st.session_state[state_key] = None

    if file_upload is not None:
        if file_upload.size > MAX_FILE_SIZE:
            st.warning("File exceeds the 15 MiB static-analysis limit.")
        else:
            file_data = file_upload.getvalue()
            file_id = (
                file_upload.name,
                hashlib.sha256(file_data).hexdigest()
            )
            if st.button("Scan File", key="scan_file"):
                st.session_state.file_scan_result = scan_file(
                    file_upload.name, file_data
                )
                st.session_state.file_scanned_id = file_id
                st.session_state.file_ai_result = None

            result = st.session_state.file_scan_result
            if result is not None and st.session_state.file_scanned_id == file_id:
                if result["risk"] == "Invalid":
                    st.warning("; ".join(result["findings"]))
                else:
                    c1, c2 = st.columns(2)
                    c1.metric("Risk Score", f"{result['score']}/100")
                    c2.metric("Risk Level", result["risk"])
                    st.progress(result["score"] / 100)
                    st.write("**SHA-256 (calculated locally):**")
                    st.code(result["sha256"])
                    st.write(f"**Detected type:** {result['file_type']}")
                    st.write(f"**Size:** {result['size_bytes']} bytes")
                    st.subheader("Security Findings")
                    for finding in result["findings"]:
                        st.write(f"- {finding}")
                    st.info("Static checks are heuristic and cannot prove file safety.")

                    st.divider()
                    st.subheader("File AI Security Explanation")
                    if st.button("Generate File AI Explanation", key="file_ai"):
                        with st.spinner("Generating file explanation..."):
                            st.session_state.file_ai_result = analyze_with_ai(
                                scan_type="File", score=result["score"],
                                risk=result["risk"], findings=result["findings"]
                            )
                    ai_result = st.session_state.file_ai_result
                    if ai_result is not None:
                        if ai_result["success"]:
                            if ai_result["explanation"].startswith("[OFFLINE TEST"):
                                st.info("Offline demonstration mode: not a live Sushi AI result.")
                            st.markdown(ai_result["explanation"])
                        else:
                            st.warning(ai_result["error"])
                    st.caption(
                        "Sushi AI explains scanner findings but cannot change the score. "
                        "File contents and SHA-256 are not sent to Sushi AI."
                    )
