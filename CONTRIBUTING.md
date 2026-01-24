# Contribuindo para VPS Guardian

Obrigado por seu interesse em contribuir! Este documento fornece diretrizes para contribuições.

## Como Contribuir

### Reportar Bugs

Abra uma issue descrevendo:
- Versão do OS
- Versão do Python
- Passos para reproduzir
- Comportamento esperado vs atual
- Logs relevantes

### Sugerir Funcionalidades

Abra uma issue descrevendo:
- Problema que resolve
- Solução proposta
- Alternativas consideradas

### Enviar Pull Requests

1. Fork o repositório
2. Crie uma branch (`git checkout -b feature/minha-feature`)
3. Faça suas alterações
4. Teste em ambiente isolado
5. Commit com mensagem clara
6. Push para seu fork
7. Abra Pull Request

## Diretrizes de Código

### Python

- Siga PEP 8
- Use type hints
- Docstrings para funções públicas
- Máximo 100 caracteres por linha

### Shell Scripts

- Use shellcheck para validação
- Comentários para lógica complexa
- Tratamento de erros adequado

### Commits

Formato:
```
tipo(escopo): descrição curta

Descrição detalhada (opcional)
```

Tipos:
- `feat`: Nova funcionalidade
- `fix`: Correção de bug
- `docs`: Documentação
- `refactor`: Refatoração
- `test`: Testes
- `chore`: Manutenção

## Testes

Antes de submeter:

1. Execute em VM de teste
2. Verifique logs do guardian
3. Teste instalação limpa
4. Teste desinstalação

## Revisão

PRs passam por:
- Revisão de código
- Teste funcional
- Verificação de segurança

## Dúvidas

Abra uma issue com tag `question`.
