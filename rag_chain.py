"""
VulnAI Manager
"""

import os
import re
import tempfile
import requests
from pathlib import Path
from langchain_ollama import ChatOllama
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma
from langchain_community.document_loaders import PyPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

CHROMA_PATH = "./chroma_db"
OLLAMA_URL = "http://localhost:11434"

SYSTEM_PROMPT = """Você é o VulnAI Manager, especialista sênior em Gestão de Vulnerabilidades.

Regras:
1. Sempre responda em português brasileiro.
2. Seja claro, objetivo e profissional.
3. Use as informações do documento enviado pelo usuário + a base de conhecimento + dados oficiais de CVEs.
4. Quando o usuário enviar um PDF, priorize o conteúdo do documento, mas complemente com seu conhecimento quando for útil.
5. Só use o formato estruturado de CVE quando o usuário perguntar especificamente sobre um CVE.

Formato para CVE específico:
**CVE:** código
**Nome / Título:** 
**Descrição:** 
**Severidade (CVSS):** 
**Vetor de Ataque:** 
**Impacto:** 
**Como funciona:** 
**Sistemas Afetados:** 
**Mitigação / Remediação:** 
**Referências:** 

Contexto do documento enviado pelo usuário:
{doc_context}

Contexto da base de conhecimento:
{kb_context}

Informações oficiais do CVE (se houver):
{cve_info}

Pergunta: {question}

Resposta:"""


def get_embeddings():
    return HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")


def buscar_cve_nvd(cve_id: str) -> str:
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id.upper()}"
        r = requests.get(url, headers={"User-Agent": "VulnAI/1.0"}, timeout=15)
        if r.status_code != 200:
            return f"Não encontrado no NVD: {cve_id}"
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return f"{cve_id} não encontrado no NVD."
        cve = vulns[0]["cve"]
        desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "Sem descrição")
        metrics = cve.get("metrics", {})
        cvss = "N/A"
        vector = "N/A"
        if "cvssMetricV31" in metrics:
            d = metrics["cvssMetricV31"][0]["cvssData"]
            cvss = f"{d.get('baseScore')} ({d.get('baseSeverity')})"
            vector = d.get("vectorString", "N/A")
        elif "cvssMetricV30" in metrics:
            d = metrics["cvssMetricV30"][0]["cvssData"]
            cvss = f"{d.get('baseScore')} ({d.get('baseSeverity')})"
            vector = d.get("vectorString", "N/A")
        refs = "\n".join([f"- {ref.get('url')}" for ref in cve.get("references", [])[:5]]) or "Nenhuma"
        return f"CVE: {cve.get('id')}\nDescrição: {desc}\nCVSS: {cvss}\nVetor: {vector}\nReferências:\n{refs}"
    except Exception as e:
        return f"Erro ao buscar CVE: {e}"


def extrair_cve(texto: str):
    m = re.search(r"CVE-\d{4}-\d{4,}", texto, re.IGNORECASE)
    return m.group(0).upper() if m else None


def processar_pdf(uploaded_file) -> Chroma | None:
    """Processa o PDF enviado e cria um vectorstore temporário"""
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
            tmp.write(uploaded_file.getvalue())
            tmp_path = tmp.name

        loader = PyPDFLoader(tmp_path)
        docs = loader.load()
        os.unlink(tmp_path)

        if not docs:
            return None

        splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
        chunks = splitter.split_documents(docs)

        embeddings = get_embeddings()
        vectorstore = Chroma.from_documents(documents=chunks, embedding=embeddings)
        return vectorstore
    except Exception as e:
        print(f"Erro ao processar PDF: {e}")
        return None


def perguntar(pergunta: str, doc_vectorstore=None) -> str:
    try:
        # Contexto do documento enviado
        doc_context = "Nenhum documento enviado."
        if doc_vectorstore is not None:
            docs = doc_vectorstore.similarity_search(pergunta, k=4)
            doc_context = "\n\n".join([d.page_content for d in docs]) if docs else "Nenhum trecho relevante encontrado no documento."

        # Contexto da base de conhecimento
        kb_context = "Base de conhecimento não disponível."
        if os.path.exists(CHROMA_PATH):
            embeddings = get_embeddings()
            kb_store = Chroma(persist_directory=CHROMA_PATH, embedding_function=embeddings)
            kb_docs = kb_store.similarity_search(pergunta, k=4)
            kb_context = "\n\n".join([d.page_content for d in kb_docs]) if kb_docs else "Nenhum trecho relevante na base."

        # CVE em tempo real
        cve_id = extrair_cve(pergunta)
        cve_info = buscar_cve_nvd(cve_id) if cve_id else "Nenhum CVE específico mencionado."

        llm = ChatOllama(model="llama3.2", base_url=OLLAMA_URL, temperature=0.2)
        prompt = ChatPromptTemplate.from_template(SYSTEM_PROMPT)

        chain = prompt | llm | StrOutputParser()

        resposta = chain.invoke({
            "doc_context": doc_context,
            "kb_context": kb_context,
            "cve_info": cve_info,
            "question": pergunta
        })
        return resposta

    except Exception as e:
        return f"Erro ao processar a pergunta:\n{str(e)}\n\nVerifique se o Ollama está rodando."
