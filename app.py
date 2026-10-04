import streamlit as st
from rag_chain import perguntar, processar_pdf

st.set_page_config(
    page_title="VulnAI Manager",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="expanded"
)

st.title("🛡️ VulnAI Manager")
st.markdown("**Assistente de IA para Gestão de Vulnerabilidades**")
st.markdown("---")

# Sidebar - Upload de PDF
with st.sidebar:
    st.header("📄 Documento")
    uploaded_file = st.file_uploader(
        "Envie um PDF para análise",
        type=["pdf"],
        help="A IA vai ler o PDF e responder junto com a base de conhecimento"
    )

    if uploaded_file is not None:
        if "doc_vectorstore" not in st.session_state or st.session_state.get("last_file") != uploaded_file.name:
            with st.spinner("Processando PDF..."):
                vectorstore = processar_pdf(uploaded_file)
                if vectorstore:
                    st.session_state.doc_vectorstore = vectorstore
                    st.session_state.last_file = uploaded_file.name
                    st.success(f"PDF carregado: {uploaded_file.name}")
                else:
                    st.error("Não foi possível processar o PDF.")
                    st.session_state.doc_vectorstore = None
        else:
            st.success(f"PDF ativo: {uploaded_file.name}")
    else:
        st.session_state.doc_vectorstore = None
        st.session_state.last_file = None
        st.info("Nenhum PDF enviado. A IA usará apenas a base de conhecimento.")

    st.markdown("---")
    st.header("Sobre")
    st.markdown("""
    A IA combina:
    - Conteúdo do PDF enviado
    - Base de conhecimento (NIST, OWASP, CVSS, EPSS, KEV...)
    - Consulta em tempo real de CVEs (NVD)
    """)
    
    if st.button("🗑️ Limpar conversa", use_container_width=True):
        st.session_state.mensagens = []
        st.rerun()

# Histórico de mensagens
if "mensagens" not in st.session_state:
    st.session_state.mensagens = []

for mensagem in st.session_state.mensagens:
    with st.chat_message(mensagem["role"]):
        st.markdown(mensagem["content"])

# Input do usuário
if prompt := st.chat_input("Digite sua pergunta..."):
    st.session_state.mensagens.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        with st.spinner("Analisando..."):
            doc_vs = st.session_state.get("doc_vectorstore", None)
            resposta = perguntar(prompt, doc_vectorstore=doc_vs)
            st.markdown(resposta)

    st.session_state.mensagens.append({"role": "assistant", "content": resposta})
