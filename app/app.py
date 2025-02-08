import streamlit as st
import pandas as pd

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
    threat_scanning(user_input)
    if(pentest):
        pentest_report()
    if(grc_compliance):
        grc_compliance_report()
    if(ra_doc):
        ra_doc_report()
    
    