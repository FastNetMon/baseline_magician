package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	_ "github.com/ClickHouse/clickhouse-go"
	"github.com/Knetic/govaluate"
	cidr "github.com/apparentlymart/go-cidr/cidr"
	"github.com/fastnetmon/fastnetmon-go"
	"github.com/pkg/errors"
	"io/ioutil"
	"log"
	"net"
	"strings"
)

type BaselineMagicianConfiguration struct {
	ClickhouseServerAddress string `json:"clickhouse_host"`
	ClickhouseServerPort    uint32 `json:"clickhouse_port"`

	// Time before current time period for which we calculate baseline
	// 7 days by default, we use seconds
	CalculationPeriod int64 `json:"calculaton_period"`

	ClickHouseDatabase string `json:"clickhouse_database"`
	ClickHouseTable    string `json:"clickhouse_table"`

	ApiUser     string `json:"api_user"`
	ApiPassword string `json:"api_password"`
	ApiHost     string `json:"api_host"`
	ApiPort     uint32 `json:"api_port"`

	// When set to true it will lead to hostgroup removal
	RemoveExistingHostgroups bool `json:"remove_existing_hostgroups"`

	GenerateIncomingPacketBaseline bool   `json:"generate_incoming_packet_threshold"`
	IncomingPacketExpression       string `json:"incoming_packet_expression"`
	GenerateIncomingBitBaseline    bool   `json:"generate_incoming_bit_threshold"`
	IncomingBitExpression          string `json:"incoming_bit_expression"`
	GenerateIncomingFlowBaseline   bool   `json:"generate_incoming_flow_threshold"`
	IncomingFlowExpression         string `json:"incoming_flow_expression"`

	// Function used to find from traffic of all hosts in network: avg or max
	AggregationFunction string `json:"aggregation_function"`
}

var configuration BaselineMagicianConfiguration

var cli_networks_list = flag.String("networks_list", "", "list of comma separated networks to run tool on")

func main() {
	flag.Parse()

	// Set default values

	// Calculate data over last 7 days by default
	configuration.CalculationPeriod = 7 * 24 * 3600
	configuration.ClickhouseServerAddress = "127.0.0.1"
	configuration.ClickhouseServerPort = 9000
	configuration.ApiUser = "admin"
	configuration.ApiPassword = "test_password"
	configuration.ApiHost = "127.0.0.1"
	configuration.ApiPort = 10007

	configuration.ClickHouseDatabase = "fastnetmon"
	configuration.ClickHouseTable = "host_metrics"

	file_as_array, err := ioutil.ReadFile("/etc/fastnetmon/baseline_magician.conf")

	if err != nil {
		log.Fatalf("Could not read configuration file with error: %v", err)
	}

	// This command will override our default configuration
	err = json.Unmarshal(file_as_array, &configuration)

	if err != nil {
		log.Fatalf("Could not read json configuration: %v", err)
	}

	// By default, let's use avg
	if configuration.AggregationFunction == "" {
		configuration.AggregationFunction = "avg"
	}

	// log.Printf("Read custom database configuration: %+v", configuration)

	// You can add: ?debug=true for debugging
	clickhouse_client, err := sql.Open("clickhouse", fmt.Sprintf("tcp://%s:%d", configuration.ClickhouseServerAddress, configuration.ClickhouseServerPort))

	if err != nil {
		log.Fatalf("Cannot connect to Clickhouse: %v", err)
	}

	if err := clickhouse_client.Ping(); err != nil {
		log.Fatalf("Cannot connect to Clickhouse: %v", err)
	}

	fastnetmon_client, err := fastnetmon.NewClient(configuration.ApiHost, configuration.ApiPort, configuration.ApiUser, configuration.ApiPassword)

	if err != nil {
		log.Fatalf("Cannot connect to client: %v", err)
	}

	networks_list := []string{}

	if *cli_networks_list != "" {
		// We will use networkst list from cli argument when specified
		for _, network := range strings.Split(*cli_networks_list, ",") {
			_, _, err := net.ParseCIDR(network)

			if err != nil {
				log.Printf("Cannot parse CIDR network: %s because of error: %v", network, err)
				continue
			}

			networks_list = append(networks_list, network)
		}

	} else {
		networks_list, err = fastnetmon_client.GetNetworks()

		if err != nil {
			log.Fatalf("Cannot get networks list from FastNetMon: %v", err)
		}
	}

	//	log.Printf("Response: %v", networks_response.Values)

	// Generate all host groups using Clickhouse data
	generate_host_groups, err := generate_hostgroups(networks_list, clickhouse_client)

	if err != nil {
		log.Fatalf("Cannot generate host groups with error: %v\n", err)
	}

	log.Printf("We generated %d host groups from Clickhouse data\n", len(generate_host_groups))

	current_hostgroups, err := fastnetmon_client.GetAllHostgroups()

	if err != nil {
		log.Fatalf("Cannot retrieve current host groups via FastNetMon API: %v", err)
	}

	// log.Printf("Retrieved %d host groups", len(current_hostgroups))
	if configuration.RemoveExistingHostgroups {
		host_groups_to_remove := []string{}

		for _, host_group_name := range current_hostgroups {
			// We ignore global host group
			if host_group_name.Name == "global" {
				continue
			}

			host_groups_to_remove = append(host_groups_to_remove, host_group_name.Name)
		}

		if len(host_groups_to_remove) > 0 {
			log.Printf("We have %d host groups to remove", len(host_groups_to_remove))
			log.Printf("Removing: %s", strings.Join(host_groups_to_remove, ","))

			for _, host_group_name := range host_groups_to_remove {
				removal_success, err := fastnetmon_client.RemoveHostGroup(host_group_name)

				// Some internal error happened
				if err != nil {
					log.Fatalf("Cannot remove host group with error: %v\n", err)
				}

				if !removal_success {
					log.Fatal("Cannot remove host group for some reasons, stop processing")
				}
			}
		} else {
			log.Printf("We do not have any host groups for removal\n")
		}
	}

	for _, new_host_group := range generate_host_groups {
		// When we do not remove all hostgroups we can remove only current one to emulate overwrite
		if !configuration.RemoveExistingHostgroups {
			log.Printf("Removing hostgroup %v", new_host_group.Name)
			removal_success, err := fastnetmon_client.RemoveHostGroup(new_host_group.Name)

			// Some internal error happened
			if err != nil {
				log.Printf("Cannot remove host group with error: %v But we continue, it's not critical\n", err)
			}

			if !removal_success {
				log.Printf("Cannot remove host group for some reasons, let's try ignoring it and continue")
			}
		}

		log.Printf("Create hostgroup %s in FastNetMon", new_host_group.Name)
		err = fastnetmon.Create_host_group_with_all_options(fastnetmon_client, new_host_group)

		if err != nil {
			log.Fatalf("Cannot create host group: %v", err)
		}
	}
}

// Generates host groups according to Clickhosue history data
func generate_hostgroups(networks_list []string, clickhouse_client *sql.DB) ([]fastnetmon.Ban_settings_t, error) {
	host_groups := []fastnetmon.Ban_settings_t{}

NETWORKS_LOOP:
	for _, network_string := range networks_list {
		address, network, err := net.ParseCIDR(network_string)

		if err != nil {
			return nil, errors.Errorf("Cannot parse: %v", err)
		}

		if address.To4() == nil {
			log.Printf("We do not support IPv6: %v\n", network_string)
			continue NETWORKS_LOOP
		}

		// It returns mask after slash for CIDR notation
		cidr_numeric_mask, _ := network.Mask.Size()

		// Number of IPs in network
		number_of_ips := cidr.AddressCount(network)

		log.Printf("Process %s with %d hosts and mask /%d", network.String(), number_of_ips, cidr_numeric_mask)

		// We must use network address here instead of hsot to avoid cases when customers added network in format like
		// 192.168.1.33/24 instead of 192.168.1.0/24
		query_in_clause := fmt.Sprintf("(IPv4StringToNum(host) >= IPv4StringToNum('%s') and IPv4StringToNum(host) <= IPv4StringToNum('%s') + %d)", network.IP.String(), network.IP.String(), number_of_ips)

		fields_for_processing := []string{
			"packets_incoming",
			"packets_outgoing",
			"bits_incoming",
			"bits_outgoing",
			"flows_incoming",
			"flows_outgoing",

			// Per protocol counters
			"tcp_packets_incoming",
			"tcp_packets_outgoing",
			"udp_packets_incoming",
			"udp_packets_outgoing",
			"icmp_packets_incoming",
			"icmp_packets_outgoing",
			"fragmented_packets_incoming",
			"fragmented_packets_outgoing",
			"tcp_syn_packets_incoming",
			"tcp_syn_packets_outgoing",
			"tcp_bits_incoming",
			"tcp_bits_outgoing",
			"udp_bits_incoming",
			"udp_bits_outgoing",
			"icmp_bits_incoming",
			"icmp_bits_outgoing",
			"fragmented_bits_incoming",
			"fragmented_bits_outgoing",
			"tcp_syn_bits_incoming",
			"tcp_syn_bits_outgoing",
		}

		fields_for_processing = processMap(fields_for_processing, func(value string) string {
			return fmt.Sprintf("toInt64(%s(%s))", configuration.AggregationFunction, value)
		})

		date_condition := fmt.Sprintf("metricDate >= toDate(now() - %d) and (metricDateTime >= now() - %d)", configuration.CalculationPeriod, configuration.CalculationPeriod)

		// date_condition = "1=1"

		query := fmt.Sprintf("select count(*), %s FROM %s.%s WHERE %s AND %s", strings.Join(fields_for_processing, ","), configuration.ClickHouseDatabase, configuration.ClickHouseTable, date_condition, query_in_clause)
		log.Printf("SQL Query: %s\n", query)

		rows, err := clickhouse_client.Query(query)

		if err != nil {
			log.Printf("Cannot execute Clickhouse query '%s' for %s with error: %v\n", query, network_string, err)
			continue NETWORKS_LOOP
		}

		log.Printf("Process network %v with %d hosts\n", network, number_of_ips)

		for rows.Next() {
			var (
				hosts_with_traffic int64
				packets_incoming   int64
				packets_outgoing   int64
				bits_incoming      int64
				bits_outgoing      int64
				flows_incoming     int64
				flows_outgoing     int64

				// Per protocol metrics
				tcp_packets_incoming        int64
				tcp_packets_outgoing        int64
				udp_packets_incoming        int64
				udp_packets_outgoing        int64
				icmp_packets_incoming       int64
				icmp_packets_outgoing       int64
				fragmented_packets_incoming int64
				fragmented_packets_outgoing int64
				tcp_syn_packets_incoming    int64
				tcp_syn_packets_outgoing    int64
				tcp_bits_incoming           int64
				tcp_bits_outgoing           int64
				udp_bits_incoming           int64
				udp_bits_outgoing           int64
				icmp_bits_incoming          int64
				icmp_bits_outgoing          int64
				fragmented_bits_incoming    int64
				fragmented_bits_outgoing    int64
				tcp_syn_bits_incoming       int64
				tcp_syn_bits_outgoing       int64
			)

			err := rows.Scan(&hosts_with_traffic, &packets_incoming, &packets_outgoing, &bits_incoming, &bits_outgoing, &flows_incoming, &flows_outgoing, &tcp_packets_incoming, &tcp_packets_outgoing, &udp_packets_incoming, &udp_packets_outgoing, &icmp_packets_incoming, &icmp_packets_outgoing, &fragmented_packets_incoming, &fragmented_packets_outgoing, &tcp_syn_packets_incoming, &tcp_syn_packets_outgoing, &tcp_bits_incoming, &tcp_bits_outgoing, &udp_bits_incoming, &udp_bits_outgoing, &icmp_bits_incoming, &icmp_bits_outgoing, &fragmented_bits_incoming, &fragmented_bits_outgoing, &tcp_syn_bits_incoming, &tcp_syn_bits_outgoing)

			if err != nil {
				return nil, errors.Errorf("Cannot read row: %v", err)
			}

			// We ignore networks without traffic, they should be handled by global host group
			if hosts_with_traffic == 0 {
				log.Printf("Skip network %s because it does not have traffic information", network_string)
				continue NETWORKS_LOOP
			}

			log.Printf("Metrics about hosts in network: %d packets_incoming: %v packets_outgoing: %v bits_incoming: %v bits_outgoing: %v flows_incoming: %v flows_outgoing: %v tcp_packets_incoming: %v tcp_packets_outgoing: %v udp_packets_incoming: %v udp_packets_outgoing: %v icmp_packets_incoming: %v icmp_packets_outgoing: %v fragmented_packets_incoming: %v fragmented_packets_outgoing: %v tcp_syn_packets_incoming: %v tcp_syn_packets_outgoing: %v tcp_bits_incoming: %v tcp_bits_outgoing: %v udp_bits_incoming: %v udp_bits_outgoing: %v icmp_bits_incoming: %v icmp_bits_outgoing: %v fragmented_bits_incoming: %v fragmented_bits_outgoing: %v tcp_syn_bits_incoming: %v tcp_syn_bits_outgoing: %v", hosts_with_traffic, packets_incoming, packets_outgoing, bits_incoming, bits_outgoing, flows_incoming, flows_outgoing, tcp_packets_incoming, tcp_packets_outgoing, udp_packets_incoming, udp_packets_outgoing, icmp_packets_incoming, icmp_packets_outgoing, fragmented_packets_incoming, fragmented_packets_outgoing, tcp_syn_packets_incoming, tcp_syn_packets_outgoing, tcp_bits_incoming, tcp_bits_outgoing, udp_bits_incoming, udp_bits_outgoing, icmp_bits_incoming, icmp_bits_outgoing, fragmented_bits_incoming, fragmented_bits_outgoing, tcp_syn_bits_incoming, tcp_syn_bits_outgoing)

			new_host_group := fastnetmon.Ban_settings_t{}
			new_host_group.Enable_ban = true

			// Filter out not allowed symbols
			new_host_group_name := network_string
			new_host_group_name = strings.Replace(new_host_group_name, ".", "_", -1)
			new_host_group_name = strings.Replace(new_host_group_name, "/", "_", -1)

			// Set host group name generated from network address
			new_host_group.Name = new_host_group_name

			// Add only current network into this host group
			new_host_group.Networks = []string{network_string}

			if configuration.GenerateIncomingPacketBaseline {
				log.Printf("I extracted following %s incoming packet rate: %d\n", configuration.AggregationFunction, packets_incoming)

				parameters := make(map[string]interface{}, 8)
				parameters["value"] = packets_incoming

				expression, err := govaluate.NewEvaluableExpression(configuration.IncomingPacketExpression)

				if err != nil {
					return nil, errors.Errorf("Cannot create expression: %v", err)
				}

				result, err := expression.Evaluate(parameters)

				if err != nil {
					return nil, errors.Errorf("Cannot evaluate expression: %v", err)
				}

				log.Printf("Threshold value: %d", cast_to_uint(result))

				if cast_to_uint(result) > 0 {
					new_host_group.Ban_for_pps = true
					new_host_group.Threshold_pps = cast_to_uint(result)
				} else {
					log.Printf("Deactivate threshold because threshold value set to zero")
				}
			}

			if configuration.GenerateIncomingBitBaseline {
				log.Printf("I extracted following %s incoming bit rate: %d\n", configuration.AggregationFunction, bits_incoming)

				parameters := make(map[string]interface{}, 8)
				parameters["value"] = bits_incoming

				expression, err := govaluate.NewEvaluableExpression(configuration.IncomingBitExpression)

				if err != nil {
					return nil, errors.Errorf("Cannot create expression: %v", err)
				}

				result, err := expression.Evaluate(parameters)

				if err != nil {
					return nil, errors.Errorf("Cannot evaluate expression: %v", err)
				}

				mbps_limit := uint(cast_to_uint(result) / 1024 / 1024)
				log.Printf("Threshold value: %d bits, %d mbps", cast_to_uint(result), mbps_limit)

				if mbps_limit > 0 {
					new_host_group.Ban_for_bandwidth = true
					new_host_group.Threshold_mbps = mbps_limit
				} else {
					log.Printf("Deactivate threshold because threshold value set to zero")
				}
			}

			if configuration.GenerateIncomingFlowBaseline {
				log.Printf("I extracted following %s incoming flow rate: %d\n", configuration.AggregationFunction, flows_incoming)

				parameters := make(map[string]interface{}, 8)
				parameters["value"] = flows_incoming

				expression, err := govaluate.NewEvaluableExpression(configuration.IncomingFlowExpression)

				if err != nil {
					return nil, errors.Errorf("Cannot create expression: %v", err)
				}

				result, err := expression.Evaluate(parameters)

				if err != nil {
					return nil, errors.Errorf("Cannot evaluate expression: %v", err)
				}

				log.Printf("Threshold value: %d", cast_to_uint(result))

				if cast_to_uint(result) > 0 {
					new_host_group.Ban_for_flows = true
					new_host_group.Threshold_flows = cast_to_uint(result)
				} else {
					log.Printf("Deactivate threshold because threshold value set to zero")
				}
			}

			log.Printf("Created hostgroup: %+v", new_host_group)

			host_groups = append(host_groups, new_host_group)
		}
	}

	return host_groups, nil
}

// Applies function to all elements
func processMap(incoming []string, f func(string) string) []string {
	outgoing := make([]string, len(incoming))

	for index, value := range incoming {
		outgoing[index] = f(value)
	}

	return outgoing
}

func cast_to_int_64(value interface{}) int64 {
	switch value.(type) {
	case float64:
		return int64(value.(float64))
	case int64:
		return value.(int64)
	}

	return 0
}

func cast_to_uint(value interface{}) uint {
	switch value.(type) {
	case float64:
		return uint(value.(float64))
	case uint:
		return value.(uint)
	}

	return 0
}
