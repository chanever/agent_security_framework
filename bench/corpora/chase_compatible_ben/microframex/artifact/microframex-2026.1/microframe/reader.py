from datetime import datetime
from os.path import basename
from .dataframe import DataFrame
from openpyxl import load_workbook
from sqlalchemy import create_engine, text

def format_datetime_with_milliseconds():
    """格式化时间为 2026-03-12 14:17:45.618 格式"""
    dt = datetime.now()
    # 获取日期时间部分（不含毫秒）
    base_time = dt.strftime("%Y-%m-%d %H:%M:%S")
    # 获取毫秒（微秒除以1000）
    milliseconds = dt.microsecond // 1000
    # 格式化毫秒为3位数，不足补零
    ms_str = f"{milliseconds:03d}"
    return f"{base_time}.{ms_str}"

def load(source, sheet_name=None, query=None):
    """
    读取数据源并返回 DataFrame

    Parameters
    ----------
    source : str
        - Excel 文件路径（.xlsx）
        - MySQL 连接字符串（mysql+pymysql://user:pwd@host/db）
    sheet_name : str, optional
        Excel sheet 名称（默认第一个 sheet）
    query : str, optional
        SQL 查询语句（仅数据库模式必填）

    Returns
    -------
    DataFrame
        microframe.DataFrame
    """

    # ========== 1. Excel ==========
    if source.lower().endswith(".xlsx"):
        wb = load_workbook(source, read_only=True, data_only=True)

        ws = wb[sheet_name] if sheet_name else wb.active

        sheet_name = sheet_name if sheet_name else ws.title

        print(f'\033[32m{format_datetime_with_milliseconds()} \033[31m| \033[0mINFO \033[31m|\033[0m 读取excel文件名称：\033[35m“{basename(source)}”\033[0m，sheet名称：\033[35m“{sheet_name}”\033[0m')

        data = list(ws.values)
        return DataFrame(data)

    # ========== 2. MySQL ==========
    if source.startswith("mysql"):
        if not query:
            raise ValueError("数据库模式下必须提供 query")

        engine = create_engine(source)

        with engine.connect() as conn:
            result = conn.execute(text(query))
            rows = result.fetchall()
            columns = result.keys()

        return DataFrame(rows, columns = columns)

    # ========== 3. 不支持的数据源 ==========
    raise ValueError(f"不支持的数据源类型: {source}")