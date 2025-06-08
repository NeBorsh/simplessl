## SimpleSSL
a small utility set of functions for easier work with aes, sha256 and b64. The readme file will describe the principle of using the repository, as well as its launch.
> [!NOTE]
> The project was written out of pure enthusiasm, and if any problems or errors arise, please write to issues
---------------------
### Examples of code usage
- `1)` `SHA256`
```cpp
std::string sha256Hash = sha256("Hello World");
```
- `2)` `Base64`
```cpp
std::string encoded = b64encode("Secret message");
std::string decoded = b64decode(encoded);
```
- `3)` `Generating random keys`
```cpp
std::vector<unsigned char> key = genRandKey(32); // 256-bit key
std::vector<unsigned char> iv = genRandIV(16);   // 128-bit IV
```
- `4)` `AES`
```cpp
std::vector<unsigned char> key = genRandKey(32);
std::vector<unsigned char> iv = genRandIV(16);

std::string plaintext = "Sensitive data";
std::vector<unsigned char> plainBytes(plaintext.begin(), plaintext.end());

std::vector<unsigned char> ciphertext = aesEncrypt(plainBytes, key, iv);
std::vector<unsigned char> decrypted = aesDecrypt(ciphertext, key, iv);
```
- `5)` `Outputting data`
```cpp
printHex(std::cout, ciphertext); // Output in hexadecimal format
printRaw(std::cout, decrypted);  // Output raw data
```
-------------
### Use in the project
**integration with your project:**
just copy the `simplessl` folder from the repository to your include folder.

**running code from repository:**
First we need to install openssl, this can be done in two ways. `Method 1` is manual installation and subsequent linking. `Method 2` is installation using a package manager and Cmake integration.
> [!IMPORTANT]
> The project from the repository uses manual linking

`Method 1)` 
1. First we need to download the binaries. For windows you can use the following site: [Win OpenSSL installer](https://slproweb.com/products/Win32OpenSSL.html) and download the installer. For Linux systems, you need to install openssl using a package manager, here's how to do it:
```bash
# Ubuntu / Debian
sudo apt-get update
sudo apt-get install libssl-dev

# RHEL/CentOS
sudo yum install openssl-devel

# Fedora
sudo dnf install openssl-devel

# Arch Linux
sudo pacman -S openssl

# macOS (Homebrew)
brew install openssl

# openSUSE
sudo zypper refresh
sudo zypper install openssl
```
2. After installation, you need to create folders for inclusion and libraries in the project. We also need to find folders with files and static libraries in the directory where we installed OpenSSL. The found files need to be copied to the corresponding folders created earlier.
3. Once we have done this, we can start linking openssl in CMakeLists.txt, which can be helped by the following code:
```cmake
target_include_directories(UrProjectName PRIVATE ${CMAKE_SOURCE_DIR}/include_folder)
target_link_directories(UrProjectName PRIVATE ${CMAKE_SOURCE_DIR}/libs_folder)

target_link_libraries(UrProjectName PRIVATE libssl.lib libsimplesslo.lib) # static library files, in the example these are windows .lib files
```
4. If everything went well, your CMake will tell you so and you will be able to compile the project.
   
`Method 2)` 
1. First, install openssl using the appropriate package manager for your operating system.
```bash
# Ubuntu / Debian
sudo apt-get update
sudo apt-get install libssl-dev

# RHEL/CentOS
sudo yum install openssl-devel

# Fedora
sudo dnf install openssl-devel

# Arch Linux
sudo pacman -S openssl

# macOS (Homebrew)
brew install openssl

# openSUSE
sudo zypper refresh
sudo zypper install openssl

# Windows (vcpkg)
vcpkg install openssl:x64-windows

# Windows (Chocolatey)
choco install openssl
```
2. Once the download process is finished, you can use the following code in your CMakeList:
```cmake
find_package(OpenSSL REQUIRED)
target_link_libraries(your_target PRIVATE OpenSSL::SSL OpenSSL::Crypto)
```
3. "If everything went well, your CMake will tell you so and you will be able to compile the project."
------------------------
> [!NOTE]
> In the future, I may supplement this project with various new functions, and the like. If you think something is necessary, you can always write an issue.
