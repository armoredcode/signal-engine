import csv


def export_csv(top_rules_list, top_files_list, clusters_dict, output_file="output.csv"):
    with open(output_file, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Type", "Identifier", "Count"])
        for rule, count in top_rules_list:
            writer.writerow(["Rule", rule, count])
        for path, count in top_files_list:
            writer.writerow(["File", path, count])
        for (rule, path), items in clusters_dict.items():
            writer.writerow(["Cluster", f"{rule} | {path}", len(items)])
    print(f"Results saved to {output_file}")
