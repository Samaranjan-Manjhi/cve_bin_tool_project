#include <iostream>
#include <fstream>
#include <cstdio>
#include <vector>
#include <string>
#include <cstring>
#include <sqlite3.h>

// Function to execute a command and return the output
std::string execute_command(const std::string& command) {
    std::string result;
    FILE* pipe = popen(command.c_str(), "r");
    if (pipe) {
        char buffer[128];
        while (!feof(pipe)) {
            if (fgets(buffer, 128, pipe) != NULL) {
                result += buffer;
            }
        }
        pclose(pipe);
    }
    return result;
}

// Function to get installed packages and their versions
std::string get_installed_packages() {
#if defined(__linux__)
    return execute_command("dpkg -l | awk '/^ii/ {print $2\"|\"$3}'");
#elif defined(__unix__) || defined(__APPLE__)
    return execute_command("rpm -qa --queryformat '%{NAME}|%{VERSION}\n'");
#endif
}

// Function to extract version from tmp file
std::string get_version_from_tmp(const std::string& product_name, const std::string& tmp_file_contents) {
    std::string version;
    std::string search_term = product_name + "|";

    size_t pos = tmp_file_contents.find(search_term);
    if (pos != std::string::npos) {
        size_t start = pos + search_term.length();
        size_t end = tmp_file_contents.find('\n', start);
        if (end != std::string::npos) {
            version = tmp_file_contents.substr(start, end - start);
        }
    }

    return version;
}

// Function to get distinct product names from the database
std::string get_distinct_products(sqlite3* db) {
    std::string query = "SELECT DISTINCT product FROM cve_range";
    std::string products;

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* product = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            products += std::string(product) + "\n";
        }

        sqlite3_finalize(stmt);
    }

    return products;
}

// Function to get CVE details for a product and version
std::vector<std::vector<std::string> > get_cve_details(sqlite3* db, const std::string& search_term, const std::string& version) {
    std::vector<std::vector<std::string> > cve_details;

    std::string query = "SELECT DISTINCT cve_range.vendor, cve_range.product, ? as version, "
        "cve_severity.cve_number, cve_severity.severity, cve_severity.score, cve_severity.data_source "
        "FROM cve_range "
        "JOIN cve_severity ON cve_range.cve_number = cve_severity.cve_number "
        "LEFT JOIN cve_exploited ON cve_severity.cve_number = cve_exploited.cve_number "
        "WHERE cve_range.product = ? AND ( "
        "(cve_range.versionStartIncluding IS NOT NULL AND cve_range.versionEndExcluding IS NOT NULL AND "
        "? >= cve_range.versionStartIncluding AND ? <= cve_range.versionEndIncluding) "
        "OR "
        "(cve_range.version = ?)) ";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, version.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, search_term.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, version.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, version.c_str(), -1, SQLITE_STATIC);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::vector<std::string> row;
            for (int i = 0; i < sqlite3_column_count(stmt); ++i) {
                const char* value = reinterpret_cast<const char*>(sqlite3_column_text(stmt, i));
                row.push_back(value);
            }
            cve_details.push_back(row);
        }

        sqlite3_finalize(stmt);
    }

    return cve_details;
}

void write_to_file(const std::vector<std::vector<std::string> >& data, const std::string& file_path) {
    std::ofstream output_file(file_path.c_str());
    if (output_file.is_open()) {
        for (size_t i = 0; i < data.size(); ++i) {
            const std::vector<std::string>& row = data[i];
            for (size_t j = 0; j < row.size(); ++j) {
                output_file << row[j] << "|";
            }
            output_file << "\n";
        }
        output_file.close();
        std::cout << "Output written to file: " << file_path << std::endl;
    } else {
        std::cerr << "Error opening output file: " << file_path << "\n";
    }
}

int main() {
    // Connect to the SQLite database
    sqlite3* db;
    //if (sqlite3_open("/opt/MicroWorld/scan_vul/div_cve.db", &db) != SQLITE_OK) {
    if (sqlite3_open("/opt/MicroWorld/var/run/cve.db", &db) != SQLITE_OK) {
        std::cerr << "Error opening the database.\n";
        return 1;
    }

    // Get distinct product names from the database and store in a tmp file
    std::string distinct_products = get_distinct_products(db);
    std::string tmp_distinct_products_path = "/opt/MicroWorld/var/run/cve_product.txt";
    std::ofstream tmp_distinct_products_file(tmp_distinct_products_path.c_str());
    if (tmp_distinct_products_file.is_open()) {
        tmp_distinct_products_file << distinct_products;
        tmp_distinct_products_file.close();
    } else {
        std::cerr << "Error creating tmp file: " << tmp_distinct_products_path << "\n";
        sqlite3_close(db);
        return 1;
    }

    // Read product names from the tmp file
    std::ifstream file(tmp_distinct_products_path.c_str());
    if (!file.is_open()) {
        std::cerr << "Error opening input file.\n";
        sqlite3_close(db);
        return 1;
    }

    // Check if tmp file of installed packages exists, create if not
    std::string tmp_file_path = "/opt/MicroWorld/var/run/cve_install.txt";
    if (!std::ifstream(tmp_file_path.c_str())) {
        std::string installed_packages = get_installed_packages();
        std::ofstream tmp_file(tmp_file_path.c_str());
        if (tmp_file.is_open()) {
            tmp_file << installed_packages;
            tmp_file.close();
        } else {
            std::cerr << "Error creating tmp file: " << tmp_file_path << "\n";
            sqlite3_close(db);
            return 1;
        }
    }

    // Read installed packages from the tmp file
    std::ifstream tmp_file(tmp_file_path.c_str());
    if (!tmp_file.is_open()) {
        std::cerr << "Error opening tmp file: " << tmp_file_path << "\n";
        sqlite3_close(db);
        return 1;
    }

    std::string tmp_file_contents((std::istreambuf_iterator<char>(tmp_file)), std::istreambuf_iterator<char>());
    tmp_file.close();

    std::vector<std::vector<std::string> > all_cve_details;

    std::string product_name;
    while (file >> product_name) {
        // Get version from the tmp file for the current product
        std::string version = get_version_from_tmp(product_name, tmp_file_contents);

        // Only perform scanning if version is found in the tmp file
        if (!version.empty()) {
            // Get CVE details for the product and version
            std::vector<std::vector<std::string> > cve_found_details = get_cve_details(db, product_name, version);
            // Add the CVE details to the combined table
            all_cve_details.insert(all_cve_details.end(), cve_found_details.begin(), cve_found_details.end());
        }
    }

    // Write the output to a file
    if (!all_cve_details.empty()) {
        std::string output_file_path = "/opt/MicroWorld/var/run/cve.txt";
        write_to_file(all_cve_details, output_file_path);
    } else {
        std::cout << "No Identified Vulnerabilities Found.\n" << std::endl;
    }

    // Close the database connection
    sqlite3_close(db);

    return 0;
}

