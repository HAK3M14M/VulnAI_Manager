"""
VulnAI Manager - Versão Avançada
- Prompt profissional
- Melhor análise de PDF
- Modo de priorização de CVEs
- Memória de conversa
- RAG ajustado
"""

import os
import re
import tempfile
import requests
from langchain_ollama import ChatOllama
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma
from langchain_community.document_loaders import PyPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

CHROMA_PATH = "./chroma_db"
OLLAMA_URL = "http://localhost:11434"

# ============================================================
# PROMPT PROFISSIONAL
# ============================================================
SYSTEM_PROMPT = """Você é o VulnAI Manager, um especialista sênior em Gestão de Vulnerabilidades, com sólida experiência em Risk-Based Vulnerability Management, CVSS, EPSS, CISA KEV, patch management e resposta a vulnerabilidades críticas.

Regras de comportamento:
1. Sempre responda em português brasileiro, de forma clara, objetiva e profissional.
2. Use linguagem técnica correta, mas acessível.
3. Quando usar informações de CVSS, EPSS, KEV ou frameworks (NIST, OWASP), mencione a fonte.
4. Em perguntas gerais, seja didático e completo.
5. Quando houver um documento PDF enviado, priorize o conteúdo dele e complemente com seu conhecimento.
6. Quando o usuário pedir priorização de CVEs, use uma abordagem Risk-Based (KEV > EPSS alto + CVSS alto > exposição do ativo > demais).
7. Só use o formato estruturado de CVE quando a pergunta for especificamente sobre um CVE.

Formato obrigatório para explicação de CVE específico:
**CVE:** 
**Nome / Título:** 
**Descrição:** 
**Severidade (CVSS):** 
**Vetor de Ataque:** 
**Impacto:** 
**Como funciona / Exploração:** 
**Sistemas Afetados:** 
**Mitigação / Remediação:** 
**Referências:** 

Histórico recente da conversa:
{chat_history}

Conteúdo do documento PDF enviado (se houver):
{doc_context}

Base de conhecimento (trechos relevantes):
{kb_context}

Dados oficiais do NVD (se houver CVE):
{cve_info}

Pergunta do usuário:
{question}

Resposta:"""


def get_embeddings():
    return HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")


def buscar_cve_nvd(cve_id: str) -> str:
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id.upper()}"
        r = requests.get(url, headers={"User-Agent": "VulnAI/1.0"}, timeout=15)
        if r.status_code != 200:
            return f"CVE {cve_id} não encontrado no NVD."
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return f"CVE {cve_id} não encontrado no NVD."
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
        return f"Erro ao consultar NVD: {e}"


def extrair_cves(texto: str) -> list:
    return list(set(re.findall(r"CVE-\d{4}-\d{4,}", texto, re.IGNORECASE)))


def processar_pdf(uploaded_file):
    """Processa PDF com melhor divisão de chunks"""
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
            tmp.write(uploaded_file.getvalue())
            tmp_path = tmp.name

        loader = PyPDFLoader(tmp_path)
        docs = loader.load()
        os.unlink(tmp_path)

        if not docs:
            return None

        # Chunks menores e com mais overlap para melhor recuperação
        splitter = RecursiveCharacterTextSplitter(
            chunk_size=800,
            chunk_overlap=250,
            separators=["\n\n", "\n", ". ", " ", ""]
        )
        chunks = splitter.split_documents(docs)

        embeddings = get_embeddings()
        vectorstore = Chroma.from_documents(documents=chunks, embedding=embeddings)
        return vectorstore
    except Exception as e:
        print(f"Erro ao processar PDF: {e}")
        return None


def resumir_pdf(doc_vectorstore) -> str:
    """Gera um resumo rápido do PDF enviado"""
    try:
        docs = doc_vectorstore.similarity_search("resumo vulnerabilidades CVE criticidade recomendações", k=6)
        conteudo = "\n\n".join([d.page_content for d in docs])
        llm = ChatOllama(model="llama3.2", base_url=OLLAMA_URL, temperature=0.1)
        prompt = f"""Faça um resumo técnico e objetivo do seguinte conteúdo de um relatório/documento de vulnerabilidades.
Destaque:
- Principais vulnerabilidades ou CVEs encontradas
- Níveis de severidade
- Sistemas/ativos afetados
- Recomendações de mitigação

Conteúdo:
{conteudo[:4000]}

Resumo:"""
        return llm.invoke(prompt).content
    except Exception as e:
        return f"Não foi possível gerar resumo: {e}"


def priorizar_cves(lista_cves: list) -> str:
    """Modo especial de priorização Risk-Based"""
    resultados = []
    for cve in lista_cves[:15]:  # limita para não demorar muito
        info = buscar_cve_nvd(cve)
        resultados.append(f"### {cve}\n{info}\n")

    llm = ChatOllama(model="llama3.2", base_url=OLLAMA_URL, temperature=0.1)
    prompt = f"""Você é um especialista em Risk-Based Vulnerability Management.
Com base nas informações abaixo, faça uma priorização profissional das CVEs.

Use esta ordem de prioridade:
1. Presente no CISA KEV (exploração confirmada)
2. CVSS alto + alta probabilidade de exploração
3. RCE / execução remota de código
4. Demais

Para cada CVE dê:
- Prioridade (Crítica / Alta / Média / Baixa)
- Justificativa curta
- Ação recomendada

Dados das CVEs:
{"".join(resultados)}

Priorização:"""
    return llm.invoke(prompt).content


def perguntar(pergunta: str, doc_vectorstore=None, chat_history: str = "") -> str:
    try:
        # Detecta se é pedido de priorização
        if re.search(r"prioriz|prioridade|ordenar.*cve|ranking.*cve", pergunta, re.IGNORECASE):
            cves = extrair_cves(pergunta)
            if cves:
                return priorizar_cves(cves)

        # Contexto do PDF
        doc_context = "Nenhum documento PDF enviado."
        if doc_vectorstore is not None:
            docs = doc_vectorstore.similarity_search(pergunta, k=5)
            doc_context = "\n\n".join([d.page_content for d in docs]) if docs else "Nenhum trecho relevante no PDF."

        # Contexto da base de conhecimento (RAG ajustado)
        kb_context = "Base de conhecimento não disponível."
        if os.path.exists(CHROMA_PATH):
            embeddings = get_embeddings()
            kb_store = Chroma(persist_directory=CHROMA_PATH, embedding_function=embeddings)
            kb_docs = kb_store.similarity_search(pergunta, k=6)
            kb_context = "\n\n".join([d.page_content for d in kb_docs]) if kb_docs else "Nenhum trecho relevante."

        # CVE individual
        cves = extrair_cves(pergunta)
        cve_info = ""
        if cves:
            cve_info = buscar_cve_nvd(cves[0])
        else:
            cve_info = "Nenhum CVE específico mencionado."

        llm = ChatOllama(model="llama3.2", base_url=OLLAMA_URL, temperature=0.15)
        prompt = ChatPromptTemplate.from_template(SYSTEM_PROMPT)
        chain = prompt | llm | StrOutputParser()

        return chain.invoke({
            "chat_history": chat_history or "Nenhum histórico.",
            "doc_context": doc_context,
            "kb_context": kb_context,
            "cve_info": cve_info,
            "question": pergunta
        })

    except Exception as e:
        return f"Erro ao processar a pergunta:\n{str(e)}\n\nVerifique se o Ollama está rodando."
