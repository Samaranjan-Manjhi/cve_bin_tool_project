#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <sqlite3.h>
#include <thread>
#include <mutex>
#include <chrono>
#include <set>
#include <iomanip> 
#include <map>
#include <experimental/filesystem>
#include <openssl/md5.h>

namespace fs = std::experimental::filesystem;

// Define a mutex for synchronization
std::mutex mutex;

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

// Function to check if a file exists
bool file_exists(const std::string& file_path) {
    std::ifstream file(file_path.c_str());
    return file.good();
}

// Function to calculate MD5 checksum of a string
std::string calculate_md5(const std::string& data) {
    MD5_CTX md5Context;
    MD5_Init(&md5Context);
    MD5_Update(&md5Context, data.c_str(), data.size());

    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5_Final(digest, &md5Context);

    std::ostringstream result;
    result << std::hex << std::setfill('0');
    for (const auto& byte : digest) {
        result << std::setw(2) << static_cast<unsigned int>(byte);
    }

    return result.str();
}

// Function to calculate MD5 checksum of a file
std::string calculate_file_md5(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return "";
    }

    std::ostringstream content;
    content << file.rdbuf();
    std::string file_content = content.str();
    return calculate_md5(file_content);
}

// Function to check MD5 checksum of two files
bool compare_file_md5(const std::string& file1, const std::string& file2) {
    std::string md5_file1 = calculate_file_md5(file1);
    std::string md5_file2 = calculate_file_md5(file2);

    return (md5_file1 == md5_file2);
}

// Function to copy .db files from /tmp/opt/ to /opt/MicroWorld/var/run/ and remove them from /tmp/opt/
void copy_db_files() {
    std::string tmp_dir = "/tmp/";
    std::string target_dir = "/opt/MicroWorld/var/run/";

    for (const auto& entry : fs::directory_iterator(tmp_dir)) {
        if (entry.path().extension() == ".db") {
            std::string source_file = entry.path();
            std::string target_file = target_dir + entry.path().filename().string();

            // Calculate MD5 checksum of the source file
            std::string md5_source = calculate_file_md5(source_file);

            // Flag to indicate whether a match is found
            bool match_found = false;

            // Check MD5 checksum of the source file against all .db files in the target directory
            for (const auto& target_entry : fs::directory_iterator(target_dir)) {
                if (target_entry.path().extension() == ".db") {
                    std::string target_db = target_entry.path();
                    
                    // Calculate MD5 checksum of the target file
                    std::string md5_target = calculate_file_md5(target_db);

                    // Check if MD5 checksums match
                    if (md5_source == md5_target) {
                        // Remove the file if MD5 checksums match
                        fs::remove(source_file);
                        std::cout << "File removed: " << source_file << std::endl;
                        match_found = true;
                        break; // Exit the loop if a match is found
                    }
                }
            }

            // Copy the file if no match is found
            if (!match_found) {
                fs::copy_file(source_file, target_file, fs::copy_options::overwrite_existing);
                std::cout << "File copied: " << source_file << " to " << target_file << std::endl;
            }
        }
    }
}



// Function to get distinct product names from the database
std::set<std::string> get_distinct_products(const std::string& db_path) {
    std::string query = "SELECT DISTINCT product FROM cve_range";
    std::set<std::string> products;

    sqlite3* db;
    if (sqlite3_open(db_path.c_str(), &db) == SQLITE_OK) {
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* product = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                products.insert(product);
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
    } else {
        std::cerr << "Error opening the database: " << db_path << "\n";
    }

    return products;
}

// Function to write the output to a file
void write_to_file(const std::set<std::string>& data, const std::string& file_path) {
    const int max_attempts = 5;
    int attempt_count = 0;

    while (attempt_count < max_attempts) {
        try {
            std::ofstream output_file(file_path.c_str(), std::ios::trunc);  // Use truncation mode to override
            if (output_file.is_open()) {
                for (const auto& product : data) {
                    output_file << product << "\n";
                }
                output_file.close();
                std::cout << "Output written to file: " << file_path << std::endl;
                break;  // Exit the loop if the file is written successfully
            } else {
                throw std::ios_base::failure("Error opening output file.");
            }
        } catch (const std::ios_base::failure& e) {
            ++attempt_count;
            std::cerr << "Attempt #" << attempt_count << ": " << e.what() << "\n";

            if (attempt_count < max_attempts) {
                // Wait for a short duration before attempting to open the file again
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            } else {
                // Display a prompt to ask whether to reload the file
                char response;
                std::cout << "The file may be open elsewhere. Do you want to reload? (y/n): ";
                std::cin >> response;

                if (response == 'y' || response == 'Y') {
                    // Retry opening the file
                    attempt_count = 0;
                } else {
                    std::cerr << "Operation aborted. File not reloaded.\n";
                    break;
                }
            }
        }
    }
}

// Function to process each database and gather distinct product names
void process_database(const std::string& db_path, std::set<std::string>& all_distinct_products) {
    std::set<std::string> distinct_products = get_distinct_products(db_path);

    // Use mutex for synchronized access to the set
    std::lock_guard<std::mutex> lock(mutex);

    // Insert distinct product names to the combined set
    all_distinct_products.insert(distinct_products.begin(), distinct_products.end());
}

// Function to get installed packages and their versions
std::set<std::string> get_installed_packages() {
    std::string result_str;
#if defined(__linux__)
    result_str = execute_command("dpkg -l | awk '/^ii/ {print $2\"|\"$3}'");
#elif defined(__unix__) || defined(__APPLE__)
    result_str = execute_command("rpm -qa --queryformat '%{NAME}|%{VERSION}\n'");
#else
    result_str = "Unsupported platform";
#endif

    // Parse the result_str into a set of strings
    std::set<std::string> result_set;
    size_t pos = 0;
    while ((pos = result_str.find("\n")) != std::string::npos) {
        result_set.insert(result_str.substr(0, pos));
        result_str.erase(0, pos + 1);
    }

    return result_set;
}


std::string get_version_from_tmp(const std::string& product_name, const std::string& tmp_file_contents) {
    size_t pos = tmp_file_contents.find(product_name + "|");

    if (pos != std::string::npos) {
        size_t start = pos + product_name.length() + 1; // Move to the character after '|'
        size_t end = tmp_file_contents.find('\n', start);

        if (end != std::string::npos) {
            return tmp_file_contents.substr(start, end - start);
        }
    }

    return "";
}

// Function to read file contents to a set of strings
void read_file_to_set(const std::string& file_path, std::set<std::string>& data) {
    std::ifstream file(file_path);
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            data.insert(line);
        }
        file.close();
    } else {
        std::cerr << "Error opening file: " << file_path << "\n";
    }
}

// Function to read file contents to a string
void read_file(const std::string& file_path, std::string& data) {
    std::ifstream file(file_path);
    if (file.is_open()) {
        data.assign((std::istreambuf_iterator<char>(file)), (std::istreambuf_iterator<char>()));
        file.close();
    } else {
        std::cerr << "Error opening file: " << file_path << "\n";
    }
}

// Function to compare files and write matching products with versions to a file
void compare_files(const std::string& distinct_products_file, const std::string& installed_packages_file, const std::string& output_file_path) {
    std::map<std::string, std::string> products;

    std::ifstream distinctProductsFile(distinct_products_file);
    if (distinctProductsFile.is_open()) {
        std::string productName;
        while (getline(distinctProductsFile, productName)) {
            products[productName] = "";
        }
        distinctProductsFile.close();
    } else {
        std::cerr << "Error opening distinct products file: " << distinct_products_file << "\n";
        return;
    }

    std::ifstream installedProductsFile(installed_packages_file);
    if (installedProductsFile.is_open()) {
        std::string line;
        while (getline(installedProductsFile, line)) {
            size_t delimiterPos = line.find("|");
            if (delimiterPos != std::string::npos) {
                std::string productName = line.substr(0, delimiterPos);
                std::string productVersion = line.substr(delimiterPos + 1);

                std::map<std::string, std::string>::iterator it = products.find(productName);
                if (it != products.end()) {
                    it->second = productVersion;
                }
            }
        }
        installedProductsFile.close();
    } else {
        std::cerr << "Error opening installed products file: " << installed_packages_file << "\n";
        return;
    }

    // Write the output to a file with pipe-separated entries
    std::ofstream output_file(output_file_path);
    if (output_file.is_open()) {
        for (const auto& pair : products) {
            if (!pair.second.empty()) { // Skip products with empty version
                output_file << pair.first <<"|"<< pair.second <<"\n";
            }
        }
        output_file.close();
        std::cout << "Output written to file: " << output_file_path << std::endl;
    } else {
        std::cerr << "Error opening output file: " << output_file_path << "\n";
    }
}

// Function to get CVE details for a product and version
std::vector<std::vector<std::string>> get_cve_details(sqlite3* db, const std::string& search_term, const std::string& version) {
    std::vector<std::vector<std::string>> cve_details;

    std::string query = "SELECT DISTINCT cve_range.vendor, cve_range.product, ? as version, "
                        "cve_severity.cve_number, cve_severity.severity, cve_severity.score "
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

void write_cve_to_file(const std::vector<std::vector<std::string>>& data, const std::string& file_path) {
    std::ofstream output_file(file_path.c_str(), std::ios::trunc);
    if (output_file.is_open()) {
        for (size_t i = 0; i < data.size(); ++i) {
            const std::vector<std::string>& row = data[i];
            for (size_t j = 0; j < row.size(); ++j) {
                output_file << row[j] << "|";
            }
            output_file << "\n";
        }
        output_file.close();
        std::cout << "CVE details written to file: " << file_path << std::endl;
    } else {
        std::cerr << "Error opening output file: " << file_path << "\n";
    }
}


// Function to read product names and versions from a file
std::vector<std::pair<std::string, std::string>> read_product_versions(const std::string& file_path) {
    std::vector<std::pair<std::string, std::string>> products;

    std::ifstream input_file(file_path);
    if (input_file.is_open()) {
        std::string line;
        while (std::getline(input_file, line)) {
            size_t delimiter_pos = line.find("|");
            if (delimiter_pos != std::string::npos) {
                std::string product_name = line.substr(0, delimiter_pos);
                std::string product_version = line.substr(delimiter_pos + 1);
                products.emplace_back(product_name, product_version);
            }
        }
        input_file.close();
    } else {
        std::cerr << "Error opening input file: " << file_path << "\n";
    }

    return products;
}

int main() {
    // Check and copy .db files from /tmp/opt/ to /opt/MicroWorld/var/run/
    copy_db_files();

    // Specify the directory path for database files
    std::string db_directory = "/opt/MicroWorld/var/run/";

    // Create a set to store the distinct product names
    std::set<std::string> all_distinct_products;

    // Create a vector to store the paths of all .db files in the specified directory
    std::vector<std::string> db_paths;

    // Iterate over the files in the directory and store the paths of .db files
    for (const auto& entry : fs::directory_iterator(db_directory)) {
        if (entry.path().extension() == ".db") {
            db_paths.push_back(entry.path());
        }
    }

    // Process each database and gather distinct product names
    for (const std::string& db_path : db_paths) {
        process_database(db_path, all_distinct_products);
    }

    // Get installed packages and write the output to a file
    std::set<std::string> installed_packages_output = get_installed_packages();
    std::string tmp_installed_packages_path = "/tmp/cve_installed.txt";
    write_to_file(installed_packages_output, tmp_installed_packages_path);

    // Write the distinct product names to a file
    std::string tmp_distinct_products_path = "/tmp/cve_products.txt";
    write_to_file(all_distinct_products, tmp_distinct_products_path);

    // Compare the two files and print matching products with versions
    std::string distinct_products_file = "/tmp/cve_products.txt";
    std::string installed_packages_file = "/tmp/cve_installed.txt";
    compare_files(distinct_products_file, installed_packages_file, "/tmp/cve_common.txt");


    // Read product names and versions from a file
    std::string product_versions_file = "/tmp/cve_common.txt"; // Replace with your actual file path
    auto products = read_product_versions(product_versions_file);

    // Vector to store the extracted CVE details
    std::vector<std::vector<std::string>> all_cve_details;

    // Open each database, process product and version, and gather CVE details
    for (const std::string& db_path : db_paths) {
        // Open the database
        sqlite3* db;
        if (sqlite3_open(db_path.c_str(), &db) == SQLITE_OK) {
            // Process each product and version
            for (const auto& product : products) {
                // Get CVE details for the product and version
                auto cve_details = get_cve_details(db, product.first, product.second);

                // Insert CVE details to the combined vector
                all_cve_details.insert(all_cve_details.end(), cve_details.begin(), cve_details.end());
            }

            // Close the database
            sqlite3_close(db);
        } else {
            std::cerr << "Error opening the database: " << db_path << "\n";
        }
    }
/*
    // Print the extracted CVE details to the console
    for (const auto& row : all_cve_details) {
        for (const auto& value : row) {
            std::cout << value << "|";
        }
        std::cout << "\n";
    }
*/
    // Write CVE details to a file (using std::ios::trunc)
    std::string cve_output_file = "/tmp/cve.txt"; // Change the path as needed
    write_cve_to_file(all_cve_details, cve_output_file);

    return 0;
}
