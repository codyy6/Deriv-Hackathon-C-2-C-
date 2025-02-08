import streamlit as st
import pandas as pd
import io
from fpdf import FPDF
from zapv2 import ZAPv2
import time
from dotenv import load_dotenv
import os
import requests
import validators

requests.packages.urllib3.disable_warnings()  # Suppress SSL warnings

load_dotenv()
ZAP_API_KEY = os.getenv("ZAP_API_KEY") 

def get_zap_vulnerabilities(target):
    if not validators.url(target):
        st.error("The provided target is not a valid URL.")
        return None

    try:
        zap = ZAPv2(apikey=ZAP_API_KEY, proxies={'http': 'http://localhost:8080', 'https': 'http://localhost:8080'})
        scanID = zap.ascan.scan(target)
        progress_bar = st.progress(0)
        progress_text = st.empty()
        while int(zap.ascan.status(scanID)) < 100:
            progress = int(zap.ascan.status(scanID))
            progress_bar.progress(progress / 100.0)
            progress_text.text(f"Scan progress: {progress}%")
            time.sleep(5)
        progress_text.text("Scan complete!")
        return zap.core.alerts(baseurl=target)
    except requests.exceptions.ProxyError as e:
        st.error(f"Failed to connect to ZAP proxy: {e}")
        return None

def save_reports_to_pdf(threat_data, pentest_data, user_input):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    # Add the user input (target link) to the top of the PDF
    pdf.cell(200, 10, txt=f"Target: {user_input}", ln=True, align='C')
    pdf.ln(10)

    def add_table_to_pdf(title, data):
        pdf.cell(200, 10, txt=title, ln=True, align='C')
        pdf.ln(10)
        for key in data.keys():
            pdf.cell(40, 10, txt=key, border=1)
        pdf.ln()
        for i in range(len(data[list(data.keys())[0]])):
            for key in data.keys():
                pdf.cell(40, 10, txt=str(data[key][i]), border=1)
            pdf.ln()
        pdf.ln(10)

    add_table_to_pdf("Threat Scanning Results", threat_data)
    if pentest_data:
        add_table_to_pdf("Pentest Report", pentest_data)

    pdf_output = io.BytesIO()
    pdf_output.write(pdf.output(dest='S').encode('latin1'))
    pdf_output.seek(0)
    return pdf_output

def threat_scanning(vulnerability_response):   
    with st.expander("Threat Scanning Results"):
        df = pd.DataFrame(vulnerability_response)
        st.markdown(
            """
            <style>
            .stTable thead tr th {
                background-color: #f0f0f0;
            }
            </style>
            """,
            unsafe_allow_html=True
        )
        st.dataframe(df, hide_index=True, use_container_width=True)
        
        # Create a bar chart for the number of each type of alert
        alert_counts = df['Alert'].value_counts()
        st.bar_chart(alert_counts)

def pentest_report(data):
    with st.expander("Pentest Report"):
        df = pd.DataFrame(data)
        st.dataframe(df, hide_index=True, use_container_width=True)
    

def main():

    st.title('C^2+C, Threat Scanning')    

    user_input = st.text_input('Enter IP or Port Here:')

    pentest = st.checkbox('Pentest')
    # grc_compliance = st.checkbox('GRC Compliance')
    # ra_doc = st.checkbox('RA Doc')

    if st.button('Submit'):
        st.markdown("---")
        
        vulnerability_scanning_result = get_zap_vulnerabilities(user_input)

        if vulnerability_scanning_result:
            simplified_results = {
            "Alert": [item['alert'] for item in vulnerability_scanning_result],
            "Suggestions": [item['solution'] for item in vulnerability_scanning_result]
            }
            threat_scanning(simplified_results)
            
            pentest_data = None
            if pentest:
                pentest_report(simplified_results)
                
            pdf_output = save_reports_to_pdf(simplified_results, pentest_data, user_input)
            st.download_button(label="Download Report as PDF", data=pdf_output, file_name="report.pdf", mime="application/pdf")
        else:
            st.write("No vulnerabilities found!")
            simplified_results = {
                "Alert": ["No vulnerabilities found"],
                "Suggestions": ["N/A"]
            }
            pdf_output = save_reports_to_pdf(simplified_results, None, user_input)
            st.download_button(label="Download Report as PDF", data=pdf_output, file_name="report.pdf", mime="application/pdf")
            
if __name__ == "__main__":
    main()