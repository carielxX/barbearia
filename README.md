LEIA ISSO PRA N SE PERDER//COMANDOS DO TERMINAL(ANTES DE RODAR O APP.PY):
# ATIVAR O AMBIENTE VIRTUAL:
python -m venv venv
venv\Scripts\activate

# INSTALAR AS DEPENDENCIAS(IMPORTANTE):
pip install -r requirements.txt

# Inicializar banco
flask initdb

# Criar admin
flask create-admin

# OPCIONAIS:

# Resetar senha admin
flask reset-admin-password

# Ver estatísticas
flask stats

# Backup do banco
flask backup-db

# Dados de demonstração
flask seed-demo

# Limpar logs antigos
flask cleanup-logs

# Listar admins
flask list-admins
////
# Caso de algum erro
feche e abra o vscode e rode denovo os comandos principais, caso o erro persista, nos contate por email(carlosdaniellopesdesouzati@gmail.com), e informe-nos o que deseja que seja alterado.
