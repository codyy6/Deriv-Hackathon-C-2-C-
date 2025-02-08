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
        st.table(df)

def pentest_report():
    with st.expander("Pentest Report"):
        st.write('Pentest')
    
def grc_compliance_report():
    with st.expander("GRC Compliance Report"):
        st.write('GRC Compliance')

def ra_doc_report():
    with st.expander("RA Documentation Report"):
        st.write('RA Doc')

st.title('C^2+C, Threat Scanning')    

user_input = st.text_input('Enter IP or Port Here:')

pentest = st.checkbox('Pentest')
grc_compliance = st.checkbox('GRC Compliance')
ra_doc = st.checkbox('RA Doc')

if st.button('Submit'):
    threat_scanning(user_input)
    if(pentest):
        pentest_report()
    if(grc_compliance):
        grc_compliance_report()
    if(ra_doc):
        ra_doc_report()
    
    