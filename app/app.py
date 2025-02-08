import streamlit as st
import pandas as pd
import io
from fpdf import FPDF

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
    pdf.output(dest='S').encode('latin1')
    pdf_output.write(pdf.output(dest='S').encode('latin1'))
    pdf_output.seek(0)
    return pdf_output

def threat_scanning(user_input):   
    with st.expander("Threat Scanning Results"):
        data = {
            'Findings': ['Finding 1', 'Finding 2', 'Finding 3'],
            'Severity': ['High', 'Medium', 'Low']
        }

        df = pd.DataFrame(data)
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
        print(df)
        st.dataframe(df, hide_index=True, use_container_width=True)

def pentest_report():
    with st.expander("Pentest Report"):
        data = {
            'Vulnerability': ['Vuln 1', 'Vuln 2', 'Vuln 3'],
            'Risk': ['Critical', 'High', 'Medium'],
            'Recommendation': ['Fix 1', 'Fix 2', 'Fix 3']
        }
        df = pd.DataFrame(data)
        st.dataframe(df, hide_index=True, use_container_width=True)
    
def grc_compliance_report():
    with st.expander("GRC Compliance Report"):
        data = {
            'Control': ['Control 1', 'Control 2', 'Control 3'],
            'Status': ['Compliant', 'Non-Compliant', 'Compliant'],
            'Action Required': ['Action 1', 'Action 2', 'Action 3']
        }
        df = pd.DataFrame(data)
        st.dataframe(df, hide_index=True, use_container_width=True)

def ra_doc_report():
    with st.expander("RA Documentation Report"):
        data = {
            'Risk': ['Risk 1', 'Risk 2', 'Risk 3'],
            'Impact': ['High', 'Medium', 'Low'],
            'Mitigation': ['Mitigation 1', 'Mitigation 2', 'Mitigation 3']
        }
        df = pd.DataFrame(data)
        st.dataframe(df, hide_index=True, use_container_width=True)

st.title('C^2+C, Threat Scanning')    

user_input = st.text_input('Enter IP or Port Here:')

pentest = st.checkbox('Pentest')
grc_compliance = st.checkbox('GRC Compliance')
ra_doc = st.checkbox('RA Doc')


if st.button('Submit'):
    st.markdown("---")
    threat_data = {
        'Findings': ['Finding 1', 'Finding 2', 'Finding 3'],
        'Severity': ['High', 'Medium', 'Low']
    }
    threat_scanning(user_input)
    
    pentest_data = None
    if pentest:
        pentest_data = {
            'Vulnerability': ['Vuln 1', 'Vuln 2', 'Vuln 3'],
            'Risk': ['Critical', 'High', 'Medium'],
            'Recommendation': ['Fix 1', 'Fix 2', 'Fix 3']
        }
        pentest_report()
    
    grc_data = None
    if grc_compliance:
        grc_data = {
            'Control': ['Control 1', 'Control 2', 'Control 3'],
            'Status': ['Compliant', 'Non-Compliant', 'Compliant'],
            'Action Required': ['Action 1', 'Action 2', 'Action 3']
        }
        grc_compliance_report()
    
    ra_data = None
    if ra_doc:
        ra_data = {
            'Risk': ['Risk 1', 'Risk 2', 'Risk 3'],
            'Impact': ['High', 'Medium', 'Low'],
            'Mitigation': ['Mitigation 1', 'Mitigation 2', 'Mitigation 3']
        }
        ra_doc_report()
    
    pdf_output = save_reports_to_pdf(threat_data, pentest_data, grc_data, ra_data)
    st.download_button(label="Download Report as PDF", data=pdf_output, file_name="report.pdf", mime="application/pdf")
    
    