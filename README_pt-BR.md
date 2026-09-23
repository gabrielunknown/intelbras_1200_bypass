# Intelbras RF 1200 / RG 1200 — Bypass Universal de Autenticação

![Severidade: Crítica](https://img.shields.io/badge/Severidade-Crítica-critical)
![CVSS 9.8](https://img.shields.io/badge/CVSS_v3.1-9.8-red)
![CVE Pendente](https://img.shields.io/badge/CVE-Pendente-lightgrey)
![Divulgação: Coordenada](https://img.shields.io/badge/Divulgação-Coordenada-blue)

Um bypass de autenticação de parâmetro único no servidor HTTP GoAhead embarcado
nos roteadores Intelbras RF 1200 e RG 1200 concede **acesso não autenticado
completo a todo o painel de administração** — cada endpoint, cada função, cada
configuração — a qualquer cliente na LAN. Nenhuma credencial é necessária em
nenhuma etapa. O dispositivo e a rede do alvo são totalmente comprometidos por
esta vulnerabilidade isoladamente.

---

## Resumo

| | |
|---|---|
| **Fabricante** | Intelbras (Brasil) |
| **Dispositivos afetados** | RF 1200 (firmware v1.2.4), RG 1200 (firmware v2.1.9) |
| **Binário vulnerável** | `/bin/httpd` — servidor web GoAhead |
| **Função vulnerável** | `R7WebsSecurityHandler` |
| **Vetor de ataque** | Rede — LAN (sem autenticação) |
| **Vetor CVSS v3.1** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Pontuação CVSS v3.1** | **9.8 Crítico** |
| **CVE** | Pendente |
| **PoC** | Disponível neste repositório — liberação aguarda prazo de divulgação coordenada |

---

## Detalhes da Vulnerabilidade

### Causa Raiz — Bypass de Autenticação

O hook de autenticação `R7WebsSecurityHandler` do GoAhead em `/bin/httpd` usa
`strstr` para verificar se a URL requisitada corresponde a um recurso estático
público:

```c
/* Simplificado a partir da desmontagem de R7WebsSecurityHandler */
if (strstr(full_url, "img/main-logo.png") != NULL) {
    /* bypass de autenticação — tratar como recurso público */
    goto allow;
}
```

`full_url` é o URI completo da requisição **incluindo a query string**. Adicionar
`?img/main-logo.png` a qualquer URL de endpoint faz `strstr` retornar não-nulo,
contornando a autenticação para **absolutamente todos os handlers e endpoints CGI**
registrados na tabela de dispatch do GoAhead — sem exceção.

Este não é um bypass parcial ou de escopo limitado. Cada handler de formulário,
cada endpoint de configuração, cada função de diagnóstico e cada endpoint de
download de arquivos no dispositivo torna-se acessível a qualquer cliente não
autenticado na rede.

### Fraqueza Secundária — Bypass do Check de CSRF

A mesma função chama `check_CSRF_attack`, que valida o header `Referer` com uma
verificação igualmente frágil por substring:

```c
if (strstr(referer, "meuintelbras") != NULL) {
    /* verificação CSRF passa */
}
```

Enviar `Referer: http://meuintelbras.local` (e `Origin: http://meuintelbras.local`)
satisfaz esse check a partir de qualquer origem. A string `"meuintelbras"` é o
prefixo de hostname da marca, hardcoded no firmware. Ambos os headers estão
incluídos no PoC.

---

## Impacto

Um atacante não autenticado com acesso à LAN (ou acesso WAN se o gerenciamento
remoto estiver habilitado) obtém **controle total sobre o dispositivo e pode
afetar diretamente todos os hosts da rede do alvo**. Isso inclui, mas não se
limita a:

- **Leitura de todos os dados sensíveis** — chaves WPA2 do Wi-Fi, credenciais
  de administrador (MD5), senhas PPPoE, segredos VPN, base de dados de
  configuração completa
- **Modificação de qualquer configuração** — alteração de senhas Wi-Fi,
  servidores DNS, regras de firewall, port forwarding, endereçamento LAN e
  qualquer outra configuração acessível pelo painel
- **Controle de todos os serviços do dispositivo** — habilitação ou desabilitação
  de interfaces, modificação de roteamento, reinicialização do dispositivo,
  operações de firmware
- **Comprometimento total do dispositivo e da rede** — o bypass alcança endpoints
  que, combinados com outras fraquezas presentes neste firmware, permitem execução
  remota de comandos como root sem autenticação; os detalhes completos da cadeia
  de execução de comandos são retidos até a divulgação responsável e pelo risco
  de uso indevido

> O download do backup de configuração demonstrado no PoC abaixo é um dos exemplos
> mais simples do que este bypass permite. É utilizado como PoC público por ser
> seguro de reproduzir, produzir saída inequívoca e não exigir etapas adicionais
> de exploração. Ele não reflete a severidade total da vulnerabilidade.

---

## Proof of Concept

> **Nota:** O script PoC completo (`poc.pl`) está disponível neste repositório.
> Sua liberação aguarda o prazo de divulgação coordenada com o fabricante.

O exemplo abaixo demonstra o download não autenticado do backup de configuração —
**uma dentre muitas** ações que o bypass torna possíveis.

### Reprodução manual (curl)

```bash
curl -s \
  -H 'Referer: http://meuintelbras.local' \
  -H 'Origin: http://meuintelbras.local' \
  "http://10.0.0.1/cgi-bin/DownloadCfg?img/main-logo.png" \
  -o config.bin

# Inspecionar credenciais em texto plano
strings -n 6 config.bin | grep -iE 'pass|psk|key|secret'
```

A string de bypass `?img/main-logo.png` funciona de forma idêntica contra qualquer
outro endpoint do dispositivo. Os headers `Referer` e `Origin` contendo
`meuintelbras` contornam o check secundário de CSRF na mesma função.

---

## Ambiente Testado

| Dispositivo | Firmware | Servidor HTTP | Resultado |
|---|---|---|---|
| Intelbras RF 1200 | v1.2.4 | GoAhead (debug build) | **Confirmado** |
| Intelbras RG 1200 | v2.1.9 | GoAhead (debug build) | **Confirmado** |

---

## Remediação

1. **Fazer parse do componente de caminho do URI** antes de qualquer verificação
   de lista de permissões. Não aplicar `strstr` ao URI completo incluindo
   parâmetros de query.

2. **Usar uma lista de permissões com correspondência exata** de caminhos não
   autenticados permitidos, em vez de busca por substring.

3. **Corrigir o check de CSRF do Referer**: validar o host dos headers `Referer`
   e `Origin` contra o endereço IP LAN configurado no dispositivo, não contra
   uma substring com nome de marca hardcoded.

---

## Linha do Tempo de Divulgação

| Data | Evento |
|---|---|
| 2026-09-22 | Vulnerabilidade confirmada no RF 1200 v1.2.4 |
| 2026-09-23 | Confirmada em segundo dispositivo: RG 1200 v2.1.9 |
| 2026-09-23 | Fabricante (Intelbras) notificado |
| 2026-09-23 | Advisory público · Submissão ao MITRE CVE |
| A definir | Resposta do fabricante / lançamento de patch |
| A definir | Liberação do PoC completo |

---

## Referências

- [MITRE CVE — Pendente](https://cve.mitre.org)
- [Página do produto Intelbras RF 1200](https://www.intelbras.com/pt-br/roteador-ac-1200-dual-band-rf-1200/)
- [Página do produto Intelbras RG 1200](https://www.intelbras.com/pt-br/roteador-ac-1200-dual-band-rg-1200/)
- [Servidor Web GoAhead — EmbedThis](https://embedthis.com/goahead/)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [CWE-200: Exposure of Sensitive Information to Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

---

## Autor

Pesquisa de segurança conduzida sob engajamento de pentest autorizado.  
Divulgação responsável coordenada com o fabricante antes da publicação.  
Detalhes adicionais de exploração retidos até patch do fabricante e prazo de divulgação responsável.
