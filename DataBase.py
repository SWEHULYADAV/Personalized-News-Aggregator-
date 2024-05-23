import sqlite3
from tabulate import tabulate

def show_tables(conn):
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print("Tables in the database:")
        for table in tables:
            print(table[0])
    except sqlite3.Error as e:
        print(f"Error fetching tables: {e}")

def show_table_contents(conn, table_name):
    try:
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM {table_name}")
        rows = cursor.fetchall()
        colnames = [desc[0] for desc in cursor.description]
        print(f"\nContents of table '{table_name}':")
        print(tabulate(rows, headers=colnames, tablefmt="grid"))
    except sqlite3.Error as e:
        print(f"Error fetching contents of table '{table_name}': {e}")

def main():
    db_name = 'news_aggregator.db'
    try:
        conn = sqlite3.connect(db_name)
        print(f"Opened database successfully: {db_name}\n")
    except sqlite3.Error as e:
        print(f"Error connecting to database: {e}")
        return
    
    try:
        show_tables(conn)
        
        tables_to_show = ['users', 'articles']
        for table in tables_to_show:
            show_table_contents(conn, table)
        
        # Example of updating a record
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET username = ? WHERE id = ?", ('new_username', 1))
        conn.commit()
        print("\nUpdated username for user with id 1.\n")
        
        # Show updated contents of the users table
        show_table_contents(conn, 'users')
    except sqlite3.Error as e:
        print(f"Error executing database operation: {e}")
    finally:
        conn.close()
        print("\nDatabase connection closed.")

if __name__ == '__main__':
    main()
