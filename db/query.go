package db

import (
	"database/sql"
	"fmt"

	_ "github.com/marcboeker/go-duckdb" // DuckDB driver

	"github.com/jedib0t/go-pretty/table"
)

func Query(query string) error {

	db, err := sql.Open("duckdb", "")
	if err != nil {
		return err
	}
	defer db.Close()

	// Query the parquet file directly
	rows, err := db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()

	// Print columns
	cols, err := rows.Columns()
	if err != nil {
		return err
	}

	w := table.NewWriter()

	header := make(table.Row, len(cols))
	for i, col := range cols {
		header[i] = col
	}
	w.AppendHeader(header)

	for rows.Next() {
		values := make([]any, len(cols))
		valuePtrs := make([]any, len(cols))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return err

		}
		w.AppendRow(values)
	}

	fmt.Println(w.Render())

	return nil
}
