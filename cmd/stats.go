package cmd

import (
	"github.com/jnfrati/xdp-inspector/db"
	"github.com/spf13/cobra"
)

func NewStatsCommand() *cobra.Command {
	stats := &cobra.Command{
		Use:   "stats",
		Short: "Show statistics",
	}

	stats.AddCommand(
		&cobra.Command{
			Use:   "top",
			Short: "Show top talkers",
			Run: func(cmd *cobra.Command, args []string) {
				filepath, _ := cmd.Flags().GetString("file")
				if err := topTalkers(filepath); err != nil {
					cmd.PrintErrln("Error:", err)
				}
			},
		},
	)

	stats.AddCommand(
		&cobra.Command{
			Use: "traffic",
			Run: func(cmd *cobra.Command, args []string) {
				filepath, _ := cmd.Flags().GetString("file")
				if err := trafficByProtocol(filepath); err != nil {
					cmd.PrintErrln("Error:", err)
				}
			},
		},
	)

	stats.AddCommand(
		&cobra.Command{
			Use: "flows",
			Run: func(cmd *cobra.Command, args []string) {
				filepath, _ := cmd.Flags().GetString("file")
				if err := flows(filepath); err != nil {
					cmd.PrintErrln("Error:", err)
				}
			},
		},
	)

	stats.PersistentFlags().StringP("file", "f", "output.parquet", "Path to the parquet file")

	return stats
}

func topTalkers(filepath string) error {

	q := `
-- Who's eating bandwidth?
SELECT source_ip, 
       COUNT(*) as packet_count,
       SUM(packet_length) as total_bytes,
       AVG(packet_length) as avg_packet_size
FROM read_parquet('` + filepath + `')
GROUP BY source_ip 
ORDER BY total_bytes DESC 
LIMIT 10;
`

	return db.Query(q)

}

func trafficByProtocol(filepath string) error {
	q := `
	-- Protocol breakdown
SELECT protocol,
       COUNT(*) as packet_count,
       SUM(packet_length) as total_bytes,
       AVG(packet_length) as avg_packet_size
FROM read_parquet('` + filepath + `')
GROUP BY protocol
ORDER BY total_bytes DESC;
`
	return db.Query(q)
}

func flows(filepath string) error {
	q := `
SELECT direction, source_ip, 
	destination_ip,
	source_port,
	destination_port,
	protocol,
	COUNT(*) as packet_count,
	SUM(packet_length) as bytes,
	MIN(timestamp) as flow_start,
	MAX(timestamp) as flow_end,
	EXTRACT(EPOCH FROM (MAX(timestamp)::TIMESTAMP - MIN(timestamp)::TIMESTAMP)) as duration_seconds
FROM read_parquet('` + filepath + `')
WHERE direction = 1
GROUP BY direction, source_ip, destination_ip, source_port, destination_port, protocol
HAVING packet_count > 10
ORDER BY bytes DESC
LIMIT 20;
	`

	return db.Query(q)
}
