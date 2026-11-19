# Controle de Formulários – versão Vercel + PostgreSQL

## Passo a passo
1. **GitHub:** crie um repositório (de preferência PRIVADO) e envie TODOS os arquivos desta pasta
   (`api/`, `public/`, `package.json`, `.gitignore`). Mantenha os nomes e pastas como estão, inclusive `api/[...path].js`.
2. **Banco:** em neon.tech (ou pelo Vercel: Storage > Neon / Marketplace) crie um projeto gratuito e copie a
   *connection string* (começa com `postgresql://`). Prefira a versão "pooled".
3. **Vercel:** vercel.com > Add New > Project > importe o repositório. Antes de clicar em Deploy, em
   *Environment Variables* cadastre:
   - `DATABASE_URL` = a connection string do banco
   - `ADMIN_PASSWORD` = senha inicial do usuário `admin` (8+ caracteres)
4. Clique em **Deploy**. Abra o endereço gerado (https://seu-projeto.vercel.app), entre com `admin` e a senha acima.
   As tabelas e os gatilhos de bloqueio são criados sozinhos no primeiro acesso.
5. Em "Usuários", crie os acessos. Para trocar a senha do admin depois, use "Redefinir senha".

## Segurança (verificada no servidor e no banco)
- Senhas com hash scrypt; sessão de 8 h; bloqueio de 5 min após 5 erros; cookie HttpOnly/Secure/SameSite.
- Lançamentos e presenças: chave única colaborador+formulário+data; UPDATE/DELETE bloqueados por gatilho do PostgreSQL.
- Auditoria imutável por gatilho. Retificação só para admin, com justificativa.
- Colaborador recebe do servidor apenas os próprios dados.

## Observações
- Backup: "Usuários > Baixar backup (JSON)". O Neon também mantém recuperação do banco no próprio painel.
- A tela atualiza a cada 15 s (só com a aba visível) para economizar uso do plano gratuito.
- Se o primeiro acesso mostrar "DATABASE_URL não configurada" ou "Defina ADMIN_PASSWORD", cadastre as variáveis e faça Redeploy.
- Código não testado contra um PostgreSQL real no ambiente de criação: relate qualquer erro.
