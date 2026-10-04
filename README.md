# 🛡️ VulnAI Manager

Assistente de IA para Gestão de Vulnerabilidades (RAG + busca de CVE em tempo real)

## Instalação

1. Instale o Ollama: https://ollama.com
2. Baixe os modelos:
```bash
ollama pull llama3.2
```

3. Instale as dependências:
```bash
pip install -r requirements.txt
```

4. Crie a base de conhecimento:
```bash
python ingest.py
```

5. Inicie a interface:
```bash
python -m streamlit run app.py
```

## Estrutura

- `app.py` → Interface
- `rag_chain.py` → Inteligência
- `ingest.py` → Cria a base de conhecimento
- `data/` → Documentos (já inclusos)
- `chroma_db/` → Base vetorial (criada automaticamente)

## Observações

- O Ollama precisa estar aberto para a IA responder.
- A primeira execução do `ingest.py` demora mais (baixa o modelo de embedding).
