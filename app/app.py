import streamlit as st
import pandas as pd
import io
from fpdf import FPDF
from zapv2 import ZAPv2
import time

ZAP_URI = st.secrets["OWASP"]["uri_key"]
ZAP_API_KEY = st.secrets["OWASP"]["api_key"]

data = {
            'Vulnerability': ['Vuln 1', 'Vuln 2', 'Vuln 3'],
            'Risk': ['Critical', 'High', 'Medium'],
            'Recommendation': ['Fix 1', 'Fix 2', 'Fix 3']
        }

def init_connection():
    return ZAPv2(apikey=ZAP_API_KEY, proxies={'http': ZAP_URI, 'https': ZAP_URI})

def get_zap_vulnerabilities(target):
    session = init_connection()
    scanID = session.ascan.scan(target)
    while int(session.ascan.status(scanID)) < 100:
        print('Scan progress %: {}'.format(session.ascan.status(scanID)))
        time.sleep(5)
        
    return session.core.alerts(baseurl=target)

def save_reports_to_pdf(threat_data, pentest_data, grc_data, ra_data):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

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
    if grc_data:
        add_table_to_pdf("GRC Compliance Report", grc_data)
    if ra_data:
        add_table_to_pdf("RA Documentation Report", ra_data)

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

def pentest_report():
    with st.expander("Pentest Report"):
        df = pd.DataFrame(data)
        st.dataframe(df, hide_index=True, use_container_width=True)
    
def grc_compliance_report(data):
    with st.expander("GRC Compliance Report"):
        df = pd.DataFrame(data)
        st.dataframe(df, hide_index=True, use_container_width=True)

def ra_doc_report(data):
    with st.expander("RA Documentation Report"):
        df = pd.DataFrame(data)
        st.dataframe(df, hide_index=True, use_container_width=True)

st.title('C^2+C, Threat Scanning')    

user_input = st.text_input('Enter IP or Port Here:')

pentest = st.checkbox('Pentest')
grc_compliance = st.checkbox('GRC Compliance')
ra_doc = st.checkbox('RA Doc')

if st.button('Submit'):
    st.markdown("---")
    
    vulnerability_scanning = get_zap_vulnerabilities(user_input)
    if vulnerability_scanning:
        threat_scanning(vulnerability_scanning)
    
    pentest_data = None
    grc_data = None
    ra_data = None
    
    if pentest:
        pentest_report()
    
    if grc_compliance:
        grc_compliance_report(vulnerability_scanning)
    
    if ra_doc:
        ra_doc_report(vulnerability_scanning)
    
    pdf_output = save_reports_to_pdf(vulnerability_scanning, pentest_data, grc_data, ra_data)
    st.download_button(label="Download Report as PDF", data=pdf_output, file_name="report.pdf", mime="application/pdf")
    
    try:
        client = init_connection()
        if client:
            st.success("Connected to database successfully!")
    except Exception as e:
        st.error(f"Database connection error: {e}")