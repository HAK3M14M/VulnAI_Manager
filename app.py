import streamlit as st
from rag_chain import perguntar, processar_pdf, resumir_pdf

st.set_page_config(
    page_title="VulnAI Manager",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="expanded"
)

st.title("🛡️ VulnAI Manager")
st.caption("Assistente profissional para Gestão de Vulnerabilidades")
st.markdown("---")

# ======================
# Estados
# ======================
if "mensagens" not in st.session_state:
    st.session_state.mensagens = []
if "doc_vectorstore" not in st.session_state:
    st.session_state.doc_vectorstore = None
if "last_file" not in st.session_state:
    st.session_state.last_file = None

# ======================
# SIDEBAR - Upload de PDF
# ======================
with st.sidebar:
    st.header("📄 Documento")
    uploaded_file = st.file_uploader(
        "Envie um PDF para análise",
        type=["pdf"],
        help="A IA vai ler o PDF e responder junto com a base de conhecimentos"
    )

    if uploaded_file is not None:
        if st.session_state.get("last_file") != uploaded_file.name:
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

            if st.button("📋 Resumir PDF", use_container_width=True):
                with st.spinner("Gerando resumo..."):
                    resumo = resumir_pdf(st.session_state.doc_vectorstore)
                    st.session_state.mensagens.append({
                        "role": "assistant",
                        "content": f"**Resumo do PDF:**\n\n{resumo}"
                    })
                    st.rerun()

            if st.button("❌ Remover PDF", use_container_width=True):
                st.session_state.doc_vectorstore = None
                st.session_state.last_file = None
                st.rerun()
    else:
        st.session_state.doc_vectorstore = None
        st.session_state.last_file = None
        st.info("Nenhum PDF enviado. A IA usará apenas a base de conhecimento.")

    st.markdown("---")
    st.header("Sobre")
    st.markdown("""
    A IA combina:
    - Conteúdo do PDF enviado
    - Base de conhecimentos (NIST, OWASP, CVSS, EPSS, KEV...)
    - Consulta em tempo real de CVEs (NVD)
    """)

    if st.button("🗑️ Limpar conversa", use_container_width=True):
        st.session_state.mensagens = []
        st.rerun()

# ======================
# Histórico de mensagens
# ======================
for mensagem in st.session_state.mensagens:
    with st.chat_message(mensagem["role"]):
        st.markdown(mensagem["content"])

# ======================
# Input do usuário
# ======================
if prompt := st.chat_input("Digite sua pergunta"):
    st.session_state.mensagens.append({"role": "user", "content": prompt})

    with st.chat_message("user"):
        st.markdown(prompt)

    # Memória da conversa
    historico = ""
    for msg in st.session_state.mensagens[-6:]:
        papel = "Usuário" if msg["role"] == "user" else "Assistente"
        historico += f"{papel}: {msg['content'][:300]}\n"

    with st.chat_message("assistant"):
        with st.spinner("Analisando..."):
            resposta = perguntar(
                prompt,
                doc_vectorstore=st.session_state.get("doc_vectorstore"),
                chat_history=historico
            )
            st.markdown(resposta)

    st.session_state.mensagens.append({"role": "assistant", "content": resposta})
