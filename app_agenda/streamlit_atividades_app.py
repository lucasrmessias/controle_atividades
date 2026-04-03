import hashlib
import hmac
import secrets
import sqlite3
from contextlib import closing
from datetime import date, datetime, timedelta
from pathlib import Path

import pandas as pd
import streamlit as st


DB_PATH = Path("atividades.db")
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
SESSION_TIMEOUT_MINUTES = 30
STATUS_OPTIONS = [
    "Pendente",
    "Em Andamento",
    "Aguardando",
    "Finalizado",
]


# =========================
# Segurança / autenticação
# =========================
def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        200_000,
    )
    return salt, hashed.hex()


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    _, computed_hash = hash_password(password, salt)
    return hmac.compare_digest(computed_hash, expected_hash)


def ensure_default_admin(conn: sqlite3.Connection) -> None:
    row = conn.execute("SELECT COUNT(*) AS total FROM usuarios").fetchone()
    total = row["total"] if row else 0
    if total > 0:
        return

    default_user = "admin"
    default_password = "Admin@123"
    salt, password_hash = hash_password(default_password)
    conn.execute(
        """
        INSERT INTO usuarios (
            username,
            nome,
            password_salt,
            password_hash,
            is_active,
            failed_attempts,
            locked_until,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, 1, 0, NULL, ?, ?)
        """,
        (
            default_user,
            "Administrador",
            salt,
            password_hash,
            datetime.utcnow().isoformat(),
            datetime.utcnow().isoformat(),
        ),
    )


def authenticate_user(username: str, password: str) -> tuple[bool, str, sqlite3.Row | None]:
    with closing(get_connection()) as conn:
        user = conn.execute(
            "SELECT * FROM usuarios WHERE lower(username) = lower(?)",
            (username.strip(),),
        ).fetchone()

        if not user:
            return False, "Usuário ou senha inválidos.", None

        if not user["is_active"]:
            return False, "Usuário inativo. Procure o administrador.", None

        locked_until = user["locked_until"]
        if locked_until:
            locked_dt = datetime.fromisoformat(locked_until)
            if datetime.utcnow() < locked_dt:
                remaining = locked_dt - datetime.utcnow()
                minutes = max(1, int(remaining.total_seconds() // 60))
                return False, f"Usuário temporariamente bloqueado. Tente novamente em {minutes} minuto(s).", None

        if not verify_password(password, user["password_salt"], user["password_hash"]):
            failed_attempts = int(user["failed_attempts"] or 0) + 1
            locked_until_value = None
            if failed_attempts >= MAX_LOGIN_ATTEMPTS:
                locked_until_value = (datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
                failed_attempts = 0

            conn.execute(
                """
                UPDATE usuarios
                SET failed_attempts = ?,
                    locked_until = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    failed_attempts,
                    locked_until_value,
                    datetime.utcnow().isoformat(),
                    user["id"],
                ),
            )
            conn.commit()

            if locked_until_value:
                return False, "Usuário bloqueado temporariamente por excesso de tentativas.", None
            return False, "Usuário ou senha inválidos.", None

        conn.execute(
            """
            UPDATE usuarios
            SET failed_attempts = 0,
                locked_until = NULL,
                last_login_at = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                datetime.utcnow().isoformat(),
                datetime.utcnow().isoformat(),
                user["id"],
            ),
        )
        conn.commit()

        fresh_user = conn.execute(
            "SELECT * FROM usuarios WHERE id = ?",
            (user["id"],),
        ).fetchone()
        return True, "Login realizado com sucesso.", fresh_user


def is_session_valid() -> bool:
    authenticated = st.session_state.get("authenticated", False)
    last_activity = st.session_state.get("last_activity_at")
    if not authenticated or not last_activity:
        return False

    if datetime.utcnow() - last_activity > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
        logout_user()
        return False

    st.session_state["last_activity_at"] = datetime.utcnow()
    return True


def login_user(user: sqlite3.Row) -> None:
    st.session_state["authenticated"] = True
    st.session_state["user_id"] = user["id"]
    st.session_state["username"] = user["username"]
    st.session_state["nome_usuario"] = user["nome"]
    st.session_state["last_activity_at"] = datetime.utcnow()


def logout_user() -> None:
    for key in [
        "authenticated",
        "user_id",
        "username",
        "nome_usuario",
        "last_activity_at",
    ]:
        st.session_state.pop(key, None)


def render_login_screen() -> None:
    col_left, col_center, col_right = st.columns([1, 1.2, 1])
    with col_center:
        st.markdown("## 🔐 Acesso ao sistema")
        st.caption("Entre com seu usuário e senha para acessar a gestão de atividades.")

        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("Usuário")
            password = st.text_input("Senha", type="password")
            submitted = st.form_submit_button("Entrar", use_container_width=True)

        st.info(
            "Primeiro acesso padrão: usuário `admin` e senha `Admin@123`. Altere isso antes de usar em equipe."
        )

        if submitted:
            if not username.strip() or not password:
                st.error("Preencha usuário e senha.")
                return

            success, message, user = authenticate_user(username, password)
            if success and user:
                login_user(user)
                st.success(message)
                st.rerun()
            else:
                st.error(message)

    st.stop()


# =========================
# Banco de dados
# =========================
def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


SEED_ATIVIDADES = [
    {
        "atividade": "view com historico do produto comprador",
        "responsavel": "Demétrius",
        "status": "Finalizado",
        "observacao": "Carga inicial",
    },
    {
        "atividade": "Validar Assistente Farma com trancrição de audio",
        "responsavel": "Lucas",
        "status": "Em Andamento",
        "observacao": "Carga inicial",
    },
    {
        "atividade": "Integração e desenho da estrutura salesforce (Clientes)",
        "responsavel": "Rodrigo",
        "status": "Aguardando",
        "observacao": "Aguardando time integração passar para Rodrigo",
    },
    {
        "atividade": "Projeto envio dados voai",
        "responsavel": "",
        "status": "Pendente",
        "observacao": "Pensar soluções",
    },
    {
        "atividade": "Separar monitoramento dados/integração",
        "responsavel": "Lucas",
        "status": "Em Andamento",
        "observacao": "Carga inicial",
    },
    {
        "atividade": "TAGs e Mascaramento de Dados Snowflake",
        "responsavel": "Não definido",
        "status": "Pendente",
        "observacao": "Carga inicial",
    },
    {
        "atividade": "Resouce Monitor Anual snowflake",
        "responsavel": "Não definido",
        "status": "Pendente",
        "observacao": "Carga inicial",
    },
    {
        "atividade": "Dicionário de dados padrão (muitos campos iguais com nomeclatura distinta)",
        "responsavel": "Não definido",
        "status": "Pendente",
        "observacao": "Carga inicial",
    },
    {
        "atividade": "Ajuste e complemento de documentação na wiki",
        "responsavel": "Não definido",
        "status": "Pendente",
        "observacao": "Carga inicial",
    },
    {
        "atividade": "Validar objeto inválidos ou sem uso camadas bronze, stage e gold",
        "responsavel": "Rodrigo",
        "status": "Aguardando",
        "observacao": "Em Validação Rodrigo",
    },
    {
        "atividade": "Construir estrura de ROLES baseando em DIREÇÃO/COORDENÇÃO/ANALISTAS",
        "responsavel": "Não definido",
        "status": "Pendente",
        "observacao": "Carga inicial",
    },
    {
        "atividade": "Tabela de TOKEN SAP vincular com a venda",
        "responsavel": "Rodrigo",
        "status": "Em Andamento",
        "observacao": "Carga inicial",
    },
    {
        "atividade": "Planilha Metas de Funcionários",
        "responsavel": "Demétrius",
        "status": "Em Andamento",
        "observacao": "Carga inicial",
    },
    {
        "atividade": "colocar task acionar api qlik cloud para transformaçẽos dag auditoria",
        "responsavel": "Lucas",
        "status": "Em Andamento",
        "observacao": "Carga inicial",
    },
    {
        "atividade": "Ruptura/Indicadores Comerciais/RH Quadro dia",
        "responsavel": "Gabriel",
        "status": "Em Andamento",
        "observacao": "Carga inicial",
    },
    {
        "atividade": "POC Centralização de Estoque",
        "responsavel": "Lucas",
        "status": "Em Andamento",
        "observacao": "Carga inicial",
    },
    {
        "atividade": "Validação Notas Fiscais",
        "responsavel": "Augusto",
        "status": "Em Andamento",
        "observacao": "Carga inicial",
    },
    {
        "atividade": "Integração API Iqvia",
        "responsavel": "Augusto",
        "status": "Em Andamento",
        "observacao": "Carga inicial",
    },
    {
        "atividade": "Vincular Quantidade de produtos com notas em transito",
        "responsavel": "Eu",
        "status": "Pendente",
        "observacao": "Segunda Feira",
    },
]


def seed_initial_data(conn: sqlite3.Connection) -> None:
    row = conn.execute("SELECT COUNT(*) AS total FROM atividades").fetchone()
    total = row["total"] if row else 0

    if total > 0:
        return

    for item in SEED_ATIVIDADES:
        data_conclusao = date.today().isoformat() if item["status"] == "Finalizado" else None
        conn.execute(
            """
            INSERT INTO atividades (
                atividade,
                responsavel,
                status,
                prazo,
                observacao,
                data_criacao,
                data_conclusao
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item["atividade"],
                item["responsavel"] if item["responsavel"] else "Não definido",
                item["status"],
                None,
                item["observacao"],
                date.today().isoformat(),
                data_conclusao,
            ),
        )


def init_db() -> None:
    with closing(get_connection()) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                nome TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                last_login_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS atividades (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                atividade TEXT NOT NULL,
                responsavel TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Pendente',
                prazo TEXT,
                observacao TEXT,
                data_criacao TEXT NOT NULL,
                data_conclusao TEXT
            )
            """
        )
        ensure_default_admin(conn)
        seed_initial_data(conn)
        conn.commit()


def create_activity(
    atividade: str,
    responsavel: str,
    status: str,
    prazo: str | None,
    observacao: str,
) -> None:
    with closing(get_connection()) as conn:
        conn.execute(
            """
            INSERT INTO atividades (
                atividade,
                responsavel,
                status,
                prazo,
                observacao,
                data_criacao,
                data_conclusao
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                atividade.strip(),
                responsavel.strip(),
                status,
                prazo,
                observacao.strip(),
                date.today().isoformat(),
                date.today().isoformat() if status == "Finalizado" else None,
            ),
        )
        conn.commit()


def update_activity(
    activity_id: int,
    atividade: str,
    responsavel: str,
    status: str,
    prazo: str | None,
    observacao: str,
) -> None:
    with closing(get_connection()) as conn:
        row = conn.execute(
            "SELECT data_conclusao FROM atividades WHERE id = ?", (activity_id,)
        ).fetchone()

        data_conclusao = row["data_conclusao"] if row else None
        if status == "Finalizado" and not data_conclusao:
            data_conclusao = date.today().isoformat()
        elif status != "Finalizado":
            data_conclusao = None

        conn.execute(
            """
            UPDATE atividades
            SET atividade = ?,
                responsavel = ?,
                status = ?,
                prazo = ?,
                observacao = ?,
                data_conclusao = ?
            WHERE id = ?
            """,
            (
                atividade.strip(),
                responsavel.strip(),
                status,
                prazo,
                observacao.strip(),
                data_conclusao,
                activity_id,
            ),
        )
        conn.commit()


def delete_activity(activity_id: int) -> None:
    with closing(get_connection()) as conn:
        conn.execute("DELETE FROM atividades WHERE id = ?", (activity_id,))
        conn.commit()


def mark_as_finished(activity_id: int) -> None:
    with closing(get_connection()) as conn:
        conn.execute(
            """
            UPDATE atividades
            SET status = 'Finalizado',
                data_conclusao = ?
            WHERE id = ?
            """,
            (date.today().isoformat(), activity_id),
        )
        conn.commit()


def get_activities() -> pd.DataFrame:
    with closing(get_connection()) as conn:
        df = pd.read_sql_query(
            "SELECT * FROM atividades ORDER BY id ASC",
            conn,
        )

    if df.empty:
        return df

    for col in ["prazo", "data_criacao", "data_conclusao"]:
        df[col] = pd.to_datetime(df[col], errors="coerce")

    return df


# =========================
# Regras de negócio
# =========================
def calcular_situacao_prazo(status: str, prazo: pd.Timestamp | None) -> str:
    if status == "Finalizado":
        return "Finalizado"

    if pd.isna(prazo):
        return "Sem prazo"

    hoje = pd.Timestamp(date.today())
    prazo_normalizado = pd.Timestamp(prazo).normalize()

    if prazo_normalizado < hoje:
        return "Atrasada"
    if prazo_normalizado == hoje:
        return "Vence hoje"
    return "No prazo"


def preparar_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df

    work_df = df.copy()
    work_df["situacao_prazo"] = work_df.apply(
        lambda row: calcular_situacao_prazo(row["status"], row["prazo"]), axis=1
    )

    work_df["prazo_fmt"] = work_df["prazo"].dt.strftime("%d/%m/%Y")
    work_df["data_criacao_fmt"] = work_df["data_criacao"].dt.strftime("%d/%m/%Y")
    work_df["data_conclusao_fmt"] = work_df["data_conclusao"].dt.strftime("%d/%m/%Y")

    work_df["prazo_fmt"] = work_df["prazo_fmt"].fillna("")
    work_df["data_criacao_fmt"] = work_df["data_criacao_fmt"].fillna("")
    work_df["data_conclusao_fmt"] = work_df["data_conclusao_fmt"].fillna("")

    return work_df


# =========================
# Interface
# =========================
def configurar_pagina() -> None:
    st.set_page_config(
        page_title="Gestão de Atividades",
        page_icon="📋",
        layout="wide",
    )

    st.markdown(
        """
        <style>
            .block-container {
                padding-top: 1.5rem;
                padding-bottom: 2rem;
            }
            .status-pill {
                padding: 0.2rem 0.55rem;
                border-radius: 999px;
                font-size: 0.85rem;
                font-weight: 600;
                display: inline-block;
            }
            .pill-finalizado { background-color: #dcfce7; color: #166534; }
            .pill-atrasada { background-color: #fee2e2; color: #991b1b; }
            .pill-vence { background-color: #fef3c7; color: #92400e; }
            .pill-prazo { background-color: #dbeafe; color: #1d4ed8; }
            .pill-sem-prazo { background-color: #e5e7eb; color: #374151; }
            .card {
                border: 1px solid #e5e7eb;
                border-radius: 16px;
                padding: 1rem;
                margin-bottom: 0.9rem;
                background: white;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.03);
            }
            .card-title {
                font-size: 1.05rem;
                font-weight: 700;
                margin-bottom: 0.2rem;
            }
            .card-meta {
                color: #4b5563;
                font-size: 0.92rem;
                margin-bottom: 0.5rem;
            }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_metricas(df: pd.DataFrame) -> None:
    total = len(df)
    finalizadas = int((df["status"] == "Finalizado").sum()) if not df.empty else 0
    em_andamento = (
        int(df["status"].isin(["Pendente", "Em Andamento", "Aguardando"]).sum())
        if not df.empty
        else 0
    )
    atrasadas = int((df["situacao_prazo"] == "Atrasada").sum()) if not df.empty else 0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total", total)
    c2.metric("Em aberto", em_andamento)
    c3.metric("Finalizadas", finalizadas)
    c4.metric("Atrasadas", atrasadas)


def render_form_cadastro() -> None:
    with st.expander("Nova atividade", expanded=True):
        with st.form("form_nova_atividade", clear_on_submit=True):
            col1, col2 = st.columns([2, 1])
            with col1:
                atividade = st.text_input("Atividade *", placeholder="Descreva a atividade")
            with col2:
                responsavel = st.text_input("Responsável *", placeholder="Nome do responsável")

            col3, col4 = st.columns(2)
            with col3:
                status = st.selectbox("Status", STATUS_OPTIONS, index=0)
            with col4:
                prazo = st.date_input("Prazo", value=None, format="DD/MM/YYYY")

            observacao = st.text_area("Observação", placeholder="Detalhes adicionais")
            submitted = st.form_submit_button("Salvar atividade", use_container_width=True)

            if submitted:
                if not atividade.strip():
                    st.error("Informe a atividade.")
                    return
                if not responsavel.strip():
                    st.error("Informe o responsável.")
                    return

                prazo_str = prazo.isoformat() if prazo else None
                create_activity(atividade, responsavel, status, prazo_str, observacao)
                st.success("Atividade cadastrada com sucesso.")
                st.rerun()


def aplicar_filtros(df: pd.DataFrame) -> pd.DataFrame:
    st.subheader("Filtros")
    c1, c2, c3, c4 = st.columns(4)

    responsaveis = ["Todos"] + sorted(df["responsavel"].dropna().astype(str).unique().tolist()) if not df.empty else ["Todos"]
    status_list = ["Todos"] + STATUS_OPTIONS
    situacoes = ["Todas", "Atrasada", "Vence hoje", "No prazo", "Sem prazo", "Finalizado"]

    with c1:
        filtro_texto = st.text_input("Buscar atividade", placeholder="Digite parte do texto")
    with c2:
        filtro_responsavel = st.selectbox("Responsável", responsaveis)
    with c3:
        filtro_status = st.selectbox("Status", status_list)
    with c4:
        filtro_situacao = st.selectbox("Situação do prazo", situacoes)

    filtered = df.copy()

    if filtro_texto:
        filtered = filtered[
            filtered["atividade"].astype(str).str.contains(filtro_texto, case=False, na=False)
        ]

    if filtro_responsavel != "Todos":
        filtered = filtered[filtered["responsavel"] == filtro_responsavel]

    if filtro_status != "Todos":
        filtered = filtered[filtered["status"] == filtro_status]

    if filtro_situacao != "Todas":
        filtered = filtered[filtered["situacao_prazo"] == filtro_situacao]

    return filtered



def pill_html(situacao: str) -> str:
    classes = {
        "Finalizado": "pill-finalizado",
        "Atrasada": "pill-atrasada",
        "Vence hoje": "pill-vence",
        "No prazo": "pill-prazo",
        "Sem prazo": "pill-sem-prazo",
    }
    css_class = classes.get(situacao, "pill-sem-prazo")
    return f'<span class="status-pill {css_class}">{situacao}</span>'



def render_cards(df: pd.DataFrame) -> None:
    st.subheader("Atividades")

    if df.empty:
        st.info("Nenhuma atividade encontrada.")
        return

    for _, row in df.iterrows():
        prazo_txt = row["prazo_fmt"] if row["prazo_fmt"] else "Sem prazo"
        conclusao_txt = row["data_conclusao_fmt"] if row["data_conclusao_fmt"] else "-"

        st.markdown(
            f"""
            <div class="card">
                <div class="card-title">#{int(row['id'])} - {row['atividade']}</div>
                <div class="card-meta">
                    <strong>Responsável:</strong> {row['responsavel']} &nbsp; | &nbsp;
                    <strong>Status:</strong> {row['status']} &nbsp; | &nbsp;
                    <strong>Prazo:</strong> {prazo_txt} &nbsp; | &nbsp;
                    <strong>Situação:</strong> {pill_html(row['situacao_prazo'])}
                </div>
                <div class="card-meta">
                    <strong>Criada em:</strong> {row['data_criacao_fmt']} &nbsp; | &nbsp;
                    <strong>Conclusão:</strong> {conclusao_txt}
                </div>
                <div>{row['observacao'] if row['observacao'] else '<em>Sem observação</em>'}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        col1, col2, col3 = st.columns([1, 1, 6])
        with col1:
            if row["status"] != "Finalizado":
                if st.button("Finalizar", key=f"finish_{row['id']}", use_container_width=True):
                    mark_as_finished(int(row["id"]))
                    st.rerun()
        with col2:
            if st.button("Excluir", key=f"delete_{row['id']}", use_container_width=True):
                delete_activity(int(row["id"]))
                st.rerun()

        with st.expander(f"Editar atividade #{int(row['id'])}"):
            with st.form(f"edit_form_{int(row['id'])}"):
                ec1, ec2 = st.columns([2, 1])
                with ec1:
                    atividade = st.text_input(
                        "Atividade",
                        value=row["atividade"],
                        key=f"atividade_{row['id']}",
                    )
                with ec2:
                    responsavel = st.text_input(
                        "Responsável",
                        value=row["responsavel"],
                        key=f"resp_{row['id']}",
                    )

                ec3, ec4 = st.columns(2)
                with ec3:
                    status_idx = STATUS_OPTIONS.index(row["status"]) if row["status"] in STATUS_OPTIONS else 0
                    status = st.selectbox(
                        "Status",
                        STATUS_OPTIONS,
                        index=status_idx,
                        key=f"status_{row['id']}",
                    )
                with ec4:
                    prazo_value = None
                    if pd.notna(row["prazo"]):
                        prazo_value = row["prazo"].date()
                    prazo = st.date_input(
                        "Prazo",
                        value=prazo_value,
                        format="DD/MM/YYYY",
                        key=f"prazo_{row['id']}",
                    )

                observacao = st.text_area(
                    "Observação",
                    value=row["observacao"] or "",
                    key=f"obs_{row['id']}",
                )

                salvar = st.form_submit_button("Salvar alterações", use_container_width=True)
                if salvar:
                    prazo_str = prazo.isoformat() if prazo else None
                    update_activity(
                        int(row["id"]),
                        atividade,
                        responsavel,
                        status,
                        prazo_str,
                        observacao,
                    )
                    st.success("Atividade atualizada com sucesso.")
                    st.rerun()



def render_tabela(df: pd.DataFrame) -> None:
    st.subheader("Visão em tabela")

    if df.empty:
        st.info("Nenhum dado para exibir na tabela.")
        return

    table_df = df[
        [
            "id",
            "atividade",
            "responsavel",
            "status",
            "situacao_prazo",
            "prazo_fmt",
            "data_criacao_fmt",
            "data_conclusao_fmt",
            "observacao",
        ]
    ].rename(
        columns={
            "id": "ID",
            "atividade": "Atividade",
            "responsavel": "Responsável",
            "status": "Status",
            "situacao_prazo": "Situação",
            "prazo_fmt": "Prazo",
            "data_criacao_fmt": "Criação",
            "data_conclusao_fmt": "Conclusão",
            "observacao": "Observação",
        }
    )

    def highlight_situacao(row):
        color = ""
        if row["Situação"] == "Atrasada":
            color = "background-color: #fee2e2"
        elif row["Situação"] == "Vence hoje":
            color = "background-color: #fef3c7"
        elif row["Situação"] == "Finalizado":
            color = "background-color: #dcfce7"
        elif row["Situação"] == "No prazo":
            color = "background-color: #dbeafe"
        elif row["Situação"] == "Sem prazo":
            color = "background-color: #e5e7eb"
        return [color] * len(row)

    st.dataframe(
        table_df.style.apply(highlight_situacao, axis=1),
        use_container_width=True,
        hide_index=True,
    )

    csv = table_df.to_csv(index=False).encode("utf-8-sig")
    st.download_button(
        label="Baixar CSV",
        data=csv,
        file_name="atividades.csv",
        mime="text/csv",
        use_container_width=False,
    )


# =========================
# Main
# =========================
def main() -> None:
    configurar_pagina()
    init_db()

    if not is_session_valid():
        render_login_screen()

    top1, top2 = st.columns([6, 1])
    with top1:
        st.title("📋 Gestão de Atividades")
        st.caption("Controle de tarefas com responsável, prazo, status e alerta de atraso.")
        st.caption(f"Usuário logado: {st.session_state.get('nome_usuario', '')} ({st.session_state.get('username', '')})")
    with top2:
        st.write("")
        st.write("")
        if st.button("Sair", use_container_width=True):
            logout_user()
            st.rerun()

    render_form_cadastro()

    raw_df = get_activities()
    prepared_df = preparar_dataframe(raw_df)

    render_metricas(prepared_df)
    st.divider()

    filtered_df = aplicar_filtros(prepared_df)
    st.divider()

    tab1, tab2 = st.tabs(["Cards", "Tabela"])
    with tab1:
        render_cards(filtered_df)
    with tab2:
        render_tabela(filtered_df)


if __name__ == "__main__":
    main()
