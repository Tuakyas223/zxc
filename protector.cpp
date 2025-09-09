#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <openssl/evp.h> // Modern OpenSSL API
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

using namespace std;

// === Вспомогательные функции ===
string read_file(const string &path) {
  ifstream file(path, ios::binary);
  if (!file)
    return "";
  ostringstream buf;
  buf << file.rdbuf();
  return buf.str();
}

string sha256(const string &data) {
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int length;

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx)
    return "";

  EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(ctx, data.c_str(), data.size());
  EVP_DigestFinal_ex(ctx, hash, &length);
  EVP_MD_CTX_free(ctx);

  stringstream ss;
  for (unsigned int i = 0; i < length; i++) {
    ss << hex << setw(2) << setfill('0') << (int)hash[i];
  }
  return ss.str();
}

bool file_exists(const string &path) { return access(path.c_str(), F_OK) == 0; }

// === Генерация защищённого бинарника ===
void generate_protected_binary(const string &binary_path,
                               const vector<int> &methods) {
  ofstream out("protected_app.cpp");
  if (!out) {
    cerr << "❌ Не удалось создать файл protected_app.cpp\n";
    return;
  }

  string binary_data = read_file(binary_path);
  if (binary_data.empty()) {
    cerr << "❌ Не удалось прочитать целевой файл\n";
    return;
  }

  string binary_hash = sha256(binary_data);

  // Кодируем бинарник как массив байт
  ostringstream encoded;
  for (unsigned char c : binary_data) {
    encoded << "0x" << hex << setw(2) << setfill('0') << (int)c << ",";
  }

  // === Генерация C++ обёртки ===
  out << R"(
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>
#include <csignal>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <openssl/evp.h>

using namespace std;

const string ORIGINAL_HASH = ")";
  out << binary_hash;
  out << R"(";

const unsigned char PAYLOAD[] = {
)";
  out << encoded.str() << "\n};\n";
  out << "const size_t PAYLOAD_SIZE = " << binary_data.size() << ";\n";

  out << R"(
string sha256(const string& data) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data.c_str(), data.size());
    EVP_DigestFinal_ex(ctx, hash, &length);
    EVP_MD_CTX_free(ctx);
    stringstream ss;
    for (unsigned int i = 0; i < length; i++)
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    return ss.str();
}

void create_temp_binary(const unsigned char* data, size_t size, const string& path) {
    ofstream file(path, ios::binary);
    file.write(reinterpret_cast<const char*>(data), size);
    file.close();
    chmod(path.c_str(), 0755);
}

bool check_integrity() {
    string payload((char*)PAYLOAD, PAYLOAD_SIZE);
    return sha256(payload) == ORIGINAL_HASH;
}

bool check_expiry(const string& expiry_date) {
    time_t now = time(0);
    struct tm expiry_tm = {};
    istringstream ss(expiry_date);
    ss >> get_time(&expiry_tm, "%Y-%m-%d");
    time_t expiry = mktime(&expiry_tm);
    return now <= expiry;
}

bool check_password(const string& correct_hash) {
    cout << "🔐 Введите пароль: ";
    string pass;
    cin >> pass;
    return sha256(pass) == correct_hash;
}

bool check_single_run() {
    string lockfile = "/tmp/." + string(getenv("USER")) + "_app.lock";
    if (file_exists(lockfile)) {
        cout << "❌ Программа уже запущена.\n";
        return false;
    }
    ofstream(lockfile) << getpid();
    signal(SIGINT, [](int) {
        remove(("/tmp/." + string(getenv("USER")) + "_app.lock").c_str());
        exit(0);
    });
    atexit([]() {
        remove(("/tmp/." + string(getenv("USER")) + "_app.lock").c_str());
    });
    return true;
}

bool file_exists(const string& path) {
    return access(path.c_str(), F_OK) == 0;
}

int main() {
    string temp_path = "/tmp/.protected_app_temp_" + to_string(getpid());

    // --- Методы защиты ---
)";

  // === Обрабатываем методы в switch с блоками ===
  for (int method : methods) {
    switch (method) {
    case 1: {
      out << R"(
    if (!check_integrity()) {
        cout << "❌ Ошибка: файл повреждён или изменён!\n";
        return 1;
    }
)";
      break;
    }
    case 2: {
      string password;
      cout << "🔐 Установите пароль для программы: ";
      cin >> password;
      out << "    if (!check_password(\"" << sha256(password) << "\")) {\n";
      out << R"(        cout << "❌ Неверный пароль!\n";
        return 1;
    }
)";
      break;
    }
    case 3: {
      string expiry;
      cout << "📅 Введите дату окончания (YYYY-MM-DD): ";
      cin >> expiry;
      out << "    if (!check_expiry(\"" << expiry << "\")) {\n";
      out << R"(        cout << "❌ Срок действия программы истёк.\n";
        return 1;
    }
)";
      break;
    }
    case 4: {
      out << R"(
    if (!check_single_run()) {
        return 1;
    }
)";
      break;
    }
    default:
      break;
    }
  }

  out << R"(
    // --- Запуск целевой программы ---
    create_temp_binary(PAYLOAD, PAYLOAD_SIZE, temp_path);
    cout << "🚀 Запуск защищённой программы...\n";
    execl(temp_path.c_str(), "app", nullptr);

    cout << "❌ Запуск не удался.\n";
    remove(temp_path.c_str());
    return 1;
}
)";

  out.close();
  cout << "✅ Сгенерирован файл protected_app.cpp\n";
}

// === Меню ===
void show_menu() {
  cout << "\n🛡️  Протектор на C++ (Linux)\n";
  cout << "Выберите методы защиты:\n";
  cout << "1) Проверка целостности\n";
  cout << "2) Пароль при запуске\n";
  cout << "3) Срок действия\n";
  cout << "4) Защита от многократного запуска\n";
  cout << "0) Готово\n";
}

int main() {
  string binary_path;
  cout << "Введите путь к исполняемому файлу: ";
  cin >> binary_path;

  if (!file_exists(binary_path)) {
    cerr << "❌ Файл не найден: " << binary_path << endl;
    return 1;
  }

  vector<int> methods;
  int choice;

  while (true) {
    show_menu();
    cout << "Выберите: ";
    cin >> choice;

    if (choice == 0)
      break;
    if (choice >= 1 && choice <= 4) {
      methods.push_back(choice);
      cout << "✅ Метод " << choice << " добавлен.\n";
    } else {
      cout << "❌ Неверный выбор.\n";
    }
  }

  if (methods.empty()) {
    cout << "❌ Не выбрано ни одного метода.\n";
    return 1;
  }

  generate_protected_binary(binary_path, methods);

  // Компиляция
  cout << "🔧 Компилируем защищённый бинарник...\n";
  int result = system("g++ protected_app.cpp -o protected_app -lssl -lcrypto");
  if (result != 0) {
    cerr << "❌ Ошибка компиляции protected_app\n";
    return 1;
  }

  cout << "🧹 Удалить временный файл protected_app.cpp? (y/n): ";
  char cleanup;
  cin >> cleanup;
  if (cleanup == 'y' || cleanup == 'Y') {
    system("rm protected_app.cpp");
  }

  cout << "\n🎉 Готово! Запускайте защищённую программу:\n";
  cout << "    ./protected_app\n";
  return 0;
}