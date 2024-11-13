import java.io.*;
import java.util.*;

public class FlowLogTagger {

    // Method to load the lookup table from a CSV file
    private static Map<String, String> loadLookupTable(String filename) throws IOException {
        Map<String, String> lookupTable = new HashMap<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length < 3) continue;
                String dstport = parts[0].trim();
                String protocol = parts[1].trim().toLowerCase();
                String tag = parts[2].trim();
                String key = (dstport + "," + protocol).trim();
                lookupTable.put(key, tag);
            }
        }
        return lookupTable;
    }

    // Method to parse flow logs and count tag matches and port/protocol combinations
    private static void parseFlowLogs(String filename, Map<String, String> lookupTable,
                                      Map<String, Integer> tagCounts,
                                      Map<String, Integer> portProtocolCounts) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split("\\s+");
                if (parts.length < 12) continue; // Skip non-formatted lines

                String dstport = parts[6].trim(); // Destination port (7th field)
                String protocolNumber = parts[7].trim(); // Protocol number (8th field)

                // Map protocol number to name
                String protocol = "icmp"; // Default to "icmp"
                if (protocolNumber.equals("6")) {
                    protocol = "tcp";
                } else if (protocolNumber.equals("17")) {
                    protocol = "udp";
                }

                // Generate lookup key
                String key = (dstport + "," + protocol).trim();

                // Check if the key exists in the lookup table
                if (lookupTable.containsKey(key)) {
                    // Found in lookup table
                    String tag = lookupTable.get(key);
                    tagCounts.put(tag, tagCounts.getOrDefault(tag, 0) + 1); // Increase tag count
                } else {
                    // Not found in lookup table, mark as "Untagged"
                    tagCounts.put("Untagged", tagCounts.getOrDefault("Untagged", 0) + 1); // Increase "Untagged" count
                }

                // Count the port/protocol combinations regardless of whether it was tagged
                String portProtocolKey = dstport + "," + protocol;
                portProtocolCounts.put(portProtocolKey, portProtocolCounts.getOrDefault(portProtocolKey, 0) + 1);
            }
        }
    }

    // Method to write the output to a file in the specified format
    private static void writeOutput(String outputFile, Map<String, Integer> tagCounts,
                                    Map<String, Integer> portProtocolCounts) throws IOException {
        try (PrintWriter writer = new PrintWriter(new FileWriter(outputFile))) {
            // Write tag counts
            writer.println("Tag Counts:");
            writer.println("Tag,Count");
            for (Map.Entry<String, Integer> entry : tagCounts.entrySet()) {
                writer.println(entry.getKey() + "," + entry.getValue());
            }

            // Write port/protocol combination counts
            writer.println("\nPort/Protocol Combination Counts:");
            writer.println("Port,Protocol,Count");
            for (Map.Entry<String, Integer> entry : portProtocolCounts.entrySet()) {
                String[] parts = entry.getKey().split(",");
                writer.println(parts[0] + "," + parts[1] + "," + entry.getValue());
            }
        }
    }

    public static void main(String[] args) {
        String lookupTableFile = "lookup.csv";
        String flowLogFile = "flow_logs.txt";
        String outputFile = "output.txt";

        try {
            // Load lookup table
            Map<String, String> lookupTable = loadLookupTable(lookupTableFile);

            // Parse flow logs and count matches
            Map<String, Integer> tagCounts = new LinkedHashMap<>();
            Map<String, Integer> portProtocolCounts = new LinkedHashMap<>();
            parseFlowLogs(flowLogFile, lookupTable, tagCounts, portProtocolCounts);

            // Write output to file
            writeOutput(outputFile, tagCounts, portProtocolCounts);

            System.out.println("Output written to " + outputFile);
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}