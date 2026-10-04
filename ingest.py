"""
VulnAI Manager - Script de Ingestão (versão final estável)
"""

import os
from pathlib import Path
from langchain_community.document_loaders import PyPDFLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma

DATA_PATH = Path("./data")
CHROMA_PATH = "./chroma_db"

def carregar_documentos():
    documentos = []
    DATA_PATH.mkdir(exist_ok=True)

    arquivos = [a for a in DATA_PATH.rglob("*") if a.is_file()]
    print(f"Arquivos encontrados: {len(arquivos)}")
    print("-" * 50)

    for arquivo in arquivos:
        print(f"Processando: {arquivo.name}")
        try:
            if arquivo.suffix.lower() == ".pdf":
                loader = PyPDFLoader(str(arquivo))
                docs = loader.load()
                documentos.extend(docs)
                print(f"   → PDF OK ({len(docs)} páginas)")
            elif arquivo.suffix.lower() in [".txt", ".md"]:
                for enc in ["utf-8", "latin-1", "cp1252"]:
                    try:
                        loader = TextLoader(str(arquivo), encoding=enc)
                        docs = loader.load()
                        documentos.extend(docs)
                        print(f"   → Texto OK")
                        break
                    except:
                        continue
        except Exception as e:
            print(f"   → Erro: {str(e)[:60]}")

    print("-" * 50)
    print(f"Total de documentos: {len(documentos)}")
    return documentos


def criar_base_vetorial():
    print("=" * 55)
    print("Criando base de conhecimento - VulnAI Manager")
    print("=" * 55)

    documentos = carregar_documentos()
    if not documentos:
        print("Nenhum documento encontrado em ./data")
        return

    print("\nDividindo em chunks...")
    splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
    chunks = splitter.split_documents(documentos)
    print(f"Chunks criados: {len(chunks)}")

    print("\nCarregando modelo de embedding...")
    embeddings = HuggingFaceEmbeddings(
        model_name="sentence-transformers/all-MiniLM-L6-v2"
    )

    if os.path.exists(CHROMA_PATH):
        import shutil
        shutil.rmtree(CHROMA_PATH)

    print("Gerando embeddings e salvando base...")
    Chroma.from_documents(
        documents=chunks,
        embedding=embeddings,
        persist_directory=CHROMA_PATH
    )

    print("\n" + "=" * 55)
    print("SUCESSO! Base criada em ./chroma_db")
    print("=" * 55)
    print("Agora rode: python -m streamlit run app.py")


if __name__ == "__main__":
    criar_base_vetorial()
