import streamlit as st
import hashlib
from scanners.url_scanner import scan_url
from scanners.email_scanner import scan_email
from scanners.qr_scanner import decode_qr
from core.ai_analyzer import analyze_with_ai
from scanners.file_scanner import scan_file, MAX_FILE_SIZE
from core.database import get_recent_scans, save_scan

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

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "URL Scanner",
    "QR Code Scanner",
    "Email Scanner",
    "File Scanner",
    "Scan History"
])

with tab1:
    st.header("URL Security Analysis")

    url = st.text_input(
        "Enter a URL to analyze:",
        placeholder="https://example.com"
    )

    # ------------------------------------------
    # INITIALIZE SESSION STATE
    # ------------------------------------------

    if "url_scan_result" not in st.session_state:
        st.session_state.url_scan_result = None

    if "url_ai_result" not in st.session_state:
        st.session_state.url_ai_result = None

    if "url_scanned_input" not in st.session_state:
        st.session_state.url_scanned_input = None

    # ------------------------------------------
    # RUN URL SECURITY SCANNER
    # ------------------------------------------

    if st.button("Scan URL"):

        # Reset previous scan and AI results
        st.session_state.url_ai_result = None
        st.session_state.url_scan_result = None
        st.session_state.url_scanned_input = None

        if not url.strip():
            st.warning("Please enter a URL.")

        else:
            result = scan_url(url)

            # Preserve results across Streamlit reruns
            st.session_state.url_scan_result = result
            st.session_state.url_scanned_input = url

            # ----------------------------------
            # SAVE VALID SCANS TO SQLITE
            # ----------------------------------

            if result["risk"] != "Invalid":
                save_scan(
                    scan_type="URL",
                    result=result
                )

    # ------------------------------------------
    # RETRIEVE PREVIOUS SCAN RESULTS
    # ------------------------------------------

    result = st.session_state.url_scan_result

    # Only display results for the scanned URL
    if (
        result is not None
        and url == st.session_state.url_scanned_input
    ):

        if result["risk"] == "Invalid":

            st.error(
                "Invalid URL: "
                + "; ".join(result["findings"])
            )

        else:

            # ----------------------------------
            # DISPLAY RISK ASSESSMENT
            # ----------------------------------

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

            # ----------------------------------
            # DISPLAY SECURITY FINDINGS
            # ----------------------------------

            st.subheader("Security Findings")

            for finding in result["findings"]:
                st.write(f"- {finding}")

            # Display appropriate risk warning
            if result["risk"] in ["High", "Critical"]:

                st.error(
                    "This URL has multiple suspicious "
                    "characteristics. Exercise caution "
                    "before interacting with it."
                )

            elif result["risk"] == "Medium":

                st.warning(
                    "Some suspicious characteristics "
                    "were detected."
                )

            else:

                st.success(
                    "No major suspicious characteristics "
                    "detected by the current rules."
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

                with st.spinner(
                    "Generating security explanation..."
                ):

                    ai_result = analyze_with_ai(
                        scan_type="URL",
                        score=result["score"],
                        risk=result["risk"],
                        findings=result["findings"]
                    )

                    # Preserve AI results across reruns
                    st.session_state.url_ai_result = ai_result

            # ----------------------------------
            # DISPLAY SUSHI AI RESPONSE
            # ----------------------------------

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

    # ------------------------------------------
    # INITIALIZE SESSION STATE
    # ------------------------------------------

    if "qr_scan_result" not in st.session_state:
        st.session_state.qr_scan_result = None

    if "qr_decoded_content" not in st.session_state:
        st.session_state.qr_decoded_content = None

    if "qr_ai_result" not in st.session_state:
        st.session_state.qr_ai_result = None

    if "qr_scanned_id" not in st.session_state:
        st.session_state.qr_scanned_id = None

    # ------------------------------------------
    # PROCESS UPLOADED QR CODE
    # ------------------------------------------

    if qr_file is not None:

        qr_bytes = qr_file.getvalue()

        # Identify the uploaded image using its hash.
        # This prevents old results appearing for a new image.
        current_qr_id = hashlib.sha256(
            qr_bytes
        ).hexdigest()

        st.image(
            qr_file,
            caption="Uploaded QR Code",
            width=250
        )

        # --------------------------------------
        # RUN QR CODE SCANNER
        # --------------------------------------

        if st.button("Scan QR Code"):

            # Clear previous scan and AI results
            st.session_state.qr_scan_result = None
            st.session_state.qr_decoded_content = None
            st.session_state.qr_ai_result = None
            st.session_state.qr_scanned_id = current_qr_id

            qr_result = decode_qr(qr_bytes)

            if not qr_result["success"]:

                st.error(qr_result["error"])

            else:

                content = qr_result["content"]

                st.session_state.qr_decoded_content = content

                # Analyze HTTP/HTTPS URLs
                if content.lower().startswith(
                    ("http://", "https://")
                ):

                    result = scan_url(content)

                    st.session_state.qr_scan_result = result

                    # ----------------------------------
                    # SAVE VALID QR SCANS TO SQLITE
                    # ----------------------------------

                    if result["risk"] != "Invalid":

                        save_scan(
                            scan_type="QR Code",
                            result=result
                        )

                else:

                    st.info(
                        "This QR code does not contain "
                        "a supported HTTP or HTTPS URL."
                    )

        # ------------------------------------------
        # DISPLAY RESULTS FOR CURRENT IMAGE ONLY
        # ------------------------------------------

        if st.session_state.qr_scanned_id == current_qr_id:

            content = st.session_state.qr_decoded_content
            result = st.session_state.qr_scan_result

            if content is not None:

                st.success("QR code decoded successfully!")

                st.write("**Decoded Content:**")
                st.code(content)

            # --------------------------------------
            # DISPLAY URL SECURITY RESULTS
            # --------------------------------------

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

                    # ----------------------------------
                    # DISPLAY SECURITY FINDINGS
                    # ----------------------------------

                    st.subheader("Security Findings")

                    for finding in result["findings"]:
                        st.write(f"- {finding}")

                    # Display risk assessment
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

                    # ----------------------------------
                    # SUSHI AI SECURITY EXPLANATION
                    # ----------------------------------

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

                            # Preserve AI results across reruns
                            st.session_state.qr_ai_result = ai_result

                    # ----------------------------------
                    # DISPLAY AI EXPLANATION
                    # ----------------------------------

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

                            st.markdown(
                                ai_result["explanation"]
                            )

                        else:

                            st.warning(
                                ai_result["error"]
                            )

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
        height=250
    )

    # ------------------------------------------
    # INITIALIZE SESSION STATE
    # ------------------------------------------

    if "email_scan_result" not in st.session_state:
        st.session_state.email_scan_result = None

    if "email_ai_result" not in st.session_state:
        st.session_state.email_ai_result = None

    if "email_scanned_input" not in st.session_state:
        st.session_state.email_scanned_input = None

    # ------------------------------------------
    # RUN EMAIL SECURITY SCANNER
    # ------------------------------------------

    if st.button("Scan Email"):

        # Clear previous scan and AI results
        st.session_state.email_scan_result = None
        st.session_state.email_ai_result = None
        st.session_state.email_scanned_input = None

        # Run existing email detection logic
        result = scan_email(email_content)

        # Preserve results across Streamlit reruns
        st.session_state.email_scan_result = result
        st.session_state.email_scanned_input = email_content

        # --------------------------------------
        # SAVE VALID EMAIL SCANS TO SQLITE
        # --------------------------------------

        if result["risk"] != "Invalid":
            save_scan(
                scan_type="Email",
                result=result
            )

    # ------------------------------------------
    # DISPLAY SAVED SCAN RESULTS
    # ------------------------------------------

    result = st.session_state.email_scan_result

    # Prevent old results appearing for different emails
    if (
        result is not None
        and email_content == st.session_state.email_scanned_input
    ):

        if result["risk"] == "Invalid":
            st.warning("; ".join(result["findings"]))

        else:

            st.subheader("Email Scan Results")

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

            # ----------------------------------
            # DISPLAY SECURITY FINDINGS
            # ----------------------------------

            st.subheader("Security Findings")

            for finding in result["findings"]:
                st.write(f"- {finding}")

            if result["risk"] in ["High", "Critical"]:

                st.error(
                    "This email contains multiple suspicious "
                    "characteristics. Exercise caution."
                )

            elif result["risk"] == "Medium":

                st.warning(
                    "Some suspicious email characteristics "
                    "were detected."
                )

            else:

                st.success(
                    "No major suspicious characteristics "
                    "detected by the current rules."
                )

            st.info(
                "These findings require context. Legitimate "
                "emails can trigger rules, and phishing "
                "emails can evade them."
            )

            # ------------------------------------------
            # SUSHI AI SECURITY EXPLANATION
            # ------------------------------------------

            st.divider()

            st.subheader("AI Security Explanation")

            st.write(
                "Use Sushi AI to explain the email's "
                "detected security indicators and "
                "recommend appropriate precautions."
            )

            if st.button(
                "Generate Email AI Explanation",
                key="email_ai"
            ):

                with st.spinner(
                    "Generating security explanation..."
                ):

                    ai_result = analyze_with_ai(
                        scan_type="Email",
                        score=result["score"],
                        risk=result["risk"],
                        findings=result["findings"]
                    )

                    # Preserve AI result across reruns
                    st.session_state.email_ai_result = ai_result

            # ----------------------------------
            # DISPLAY AI EXPLANATION
            # ----------------------------------

            ai_result = st.session_state.email_ai_result

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
                "The original email scanner determines "
                "the risk score and classification. "
                "Only scan findings are sent to Sushi AI, "
                "not the full email content."
            )

with tab4:
    st.header("File Security Analysis")

    st.caption(
        "Static file analysis using SHA-256 hashing, file signatures, "
        "extensions, and suspicious file characteristics. "
        "Files are never executed or uploaded to Sushi AI."
    )

    file_upload = st.file_uploader(
        "Upload a file for security analysis",
        key="file_upload"
    )

    # ------------------------------------------
    # INITIALIZE SESSION STATE
    # ------------------------------------------

    if "file_scan_result" not in st.session_state:
        st.session_state.file_scan_result = None

    if "file_ai_result" not in st.session_state:
        st.session_state.file_ai_result = None

    if "file_scanned_id" not in st.session_state:
        st.session_state.file_scanned_id = None

    # ------------------------------------------
    # PROCESS UPLOADED FILE
    # ------------------------------------------

    if file_upload is not None:

        # Validate size before reading the file
        if file_upload.size > MAX_FILE_SIZE:
            st.error(
                "File exceeds the 15 MiB static-analysis limit."
            )

        else:
            file_data = file_upload.getvalue()

            # Unique identifier for this uploaded file
            # Prevents displaying results for a different file
            file_id = (
                file_upload.name,
                hashlib.sha256(file_data).hexdigest()
            )

            # --------------------------------------
            # RUN FILE SECURITY SCANNER
            # --------------------------------------

            if st.button("Scan File", key="scan_file"):

                # Clear previous scan and AI results
                st.session_state.file_scan_result = None
                st.session_state.file_ai_result = None
                st.session_state.file_scanned_id = None

                # Perform static file analysis
                result = scan_file(
                    file_upload.name,
                    file_data
                )

                # Preserve results across Streamlit reruns
                st.session_state.file_scan_result = result
                st.session_state.file_scanned_id = file_id

                # ----------------------------------
                # SAVE VALID FILE SCANS TO SQLITE
                # ----------------------------------

                if result["risk"] != "Invalid":

                    save_scan(
                        scan_type="File",
                        result=result
                    )

            # --------------------------------------
            # RETRIEVE CURRENT FILE SCAN RESULTS
            # --------------------------------------

            result = st.session_state.file_scan_result

            if (
                result is not None
                and st.session_state.file_scanned_id == file_id
            ):

                if result["risk"] == "Invalid":

                    st.warning(
                        "; ".join(result["findings"])
                    )

                else:

                    # ----------------------------------
                    # DISPLAY RISK ASSESSMENT
                    # ----------------------------------

                    st.subheader("File Scan Results")

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

                    # ----------------------------------
                    # DISPLAY FILE INFORMATION
                    # ----------------------------------

                    st.subheader("File Information")

                    st.write("**Filename:**")
                    st.text(result["filename"])

                    st.write(
                        "**File Size:**",
                        result["size_bytes"],
                        "bytes"
                    )

                    st.write(
                        "**Detected File Type:**",
                        result["file_type"]
                    )

                    st.write("**SHA-256 Hash:**")
                    st.code(result["sha256"])

                    # ----------------------------------
                    # DISPLAY SECURITY FINDINGS
                    # ----------------------------------

                    st.subheader("Security Findings")

                    for finding in result["findings"]:
                        st.write(f"- {finding}")

                    # Display appropriate risk warning
                    if result["risk"] in ["High", "Critical"]:

                        st.error(
                            "This file contains potentially dangerous "
                            "characteristics. Avoid opening or executing "
                            "it unless its origin is verified."
                        )

                    elif result["risk"] == "Medium":

                        st.warning(
                            "Some suspicious file characteristics "
                            "were detected."
                        )

                    else:

                        st.success(
                            "No elevated-risk characteristics detected "
                            "by the current static checks."
                        )

                    # ----------------------------------
                    # SUSHI AI SECURITY EXPLANATION
                    # ----------------------------------

                    st.divider()

                    st.subheader("AI Security Explanation")

                    st.write(
                        "Generate a security explanation and "
                        "recommended precautions using Sushi AI."
                    )

                    if st.button(
                        "Generate File AI Explanation",
                        key="file_ai"
                    ):

                        with st.spinner(
                            "Generating security explanation..."
                        ):

                            ai_result = analyze_with_ai(
                                scan_type="File",
                                score=result["score"],
                                risk=result["risk"],
                                findings=result["findings"]
                            )

                            # Preserve AI result across reruns
                            st.session_state.file_ai_result = ai_result

                    # ----------------------------------
                    # DISPLAY SUSHI AI RESPONSE
                    # ----------------------------------

                    ai_result = st.session_state.file_ai_result

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
                        "Sushi AI explains the scanner's findings but "
                        "does not change its risk score. File contents "
                        "and SHA-256 hashes are not sent to Sushi AI. "
                        "Static analysis cannot guarantee file safety."
                    )

with tab5:
    st.header("Scan History Dashboard")

    st.write(
        "Review previous security scan results stored "
        "locally in the SQLite database."
    )

    st.caption(
        "Timestamps are recorded in UTC. "
        "Only scan findings, scores, and classifications "
        "are saved."
    )

    scans = get_recent_scans(limit=50)

    if not scans:
        st.info(
            "No scan history is available yet. "
            "Complete a security scan to begin."
        )

    else:
        st.metric(
            "Total Recent Scans",
            len(scans)
        )

        st.subheader("Recent Security Assessments")

        display_rows = []

        for scan in scans:
            display_rows.append({
                "Scan ID": scan["id"],
                "Timestamp (UTC)": scan["timestamp"],
                "Scanner": scan["scan_type"],
                "Risk Score": scan["score"],
                "Risk Level": scan["risk"],
                "Security Findings": "; ".join(
                    scan["findings"]
                )
            })

        st.dataframe(
            display_rows,
            use_container_width=True,
            hide_index=True
        )

        st.caption(
            "Displaying up to 50 of the most recent scans. "
            "The database remains on this computer."
        )
