#pragma once

#include <cstddef>
#include <filesystem>
#include <limits>
#include <string_view>
#include <stdexcept>
#include <system_error>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

class MappedFile {
public:
    explicit MappedFile(const std::filesystem::path& path) {
#ifdef _WIN32
        HANDLE file = CreateFileW(
            path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );
        if (file == INVALID_HANDLE_VALUE) {
            throw std::system_error(
                static_cast<int>(GetLastError()),
                std::system_category(),
                "Could not open source file"
            );
        }

        LARGE_INTEGER file_size{};
        if (!GetFileSizeEx(file, &file_size)) {
            const auto error = GetLastError();
            CloseHandle(file);
            throw std::system_error(
                static_cast<int>(error),
                std::system_category(),
                "Could not read source file size"
            );
        }
        if (file_size.QuadPart < 0 ||
            static_cast<unsigned long long>(file_size.QuadPart) >
                static_cast<unsigned long long>(std::numeric_limits<std::size_t>::max())) {
            CloseHandle(file);
            throw std::overflow_error("Source file is too large to map");
        }

        size_ = static_cast<std::size_t>(file_size.QuadPart);
        if (size_ == 0) {
            file_handle_ = file;
            valid_ = true;
            return;
        }

        HANDLE mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (mapping == nullptr) {
            const auto error = GetLastError();
            CloseHandle(file);
            throw std::system_error(
                static_cast<int>(error),
                std::system_category(),
                "Could not create source file mapping"
            );
        }

        const auto* data = static_cast<const char*>(MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0));
        if (data == nullptr) {
            const auto error = GetLastError();
            CloseHandle(mapping);
            CloseHandle(file);
            throw std::system_error(
                static_cast<int>(error),
                std::system_category(),
                "Could not map source file"
            );
        }

        file_handle_ = file;
        mapping_handle_ = mapping;
        data_ = data;
#else
        const int file = open(path.c_str(), O_RDONLY);
        if (file < 0) {
            throw std::system_error(errno, std::generic_category(), "Could not open source file");
        }

        struct stat info {};
        if (fstat(file, &info) != 0) {
            const int error = errno;
            close(file);
            throw std::system_error(error, std::generic_category(), "Could not read source file size");
        }
        if (info.st_size < 0 ||
            static_cast<unsigned long long>(info.st_size) >
                static_cast<unsigned long long>(std::numeric_limits<std::size_t>::max())) {
            close(file);
            throw std::overflow_error("Source file is too large to map");
        }

        size_ = static_cast<std::size_t>(info.st_size);
        if (size_ == 0) {
            file_descriptor_ = file;
            valid_ = true;
            return;
        }

        void* mapping = mmap(nullptr, size_, PROT_READ, MAP_PRIVATE, file, 0);
        if (mapping == MAP_FAILED) {
            const int error = errno;
            close(file);
            throw std::system_error(error, std::generic_category(), "Could not map source file");
        }

#ifdef MADV_SEQUENTIAL
        madvise(mapping, size_, MADV_SEQUENTIAL);
#endif
        file_descriptor_ = file;
        data_ = static_cast<const char*>(mapping);
#endif
        valid_ = true;
    }

    ~MappedFile() {
#ifdef _WIN32
        if (data_ != nullptr) {
            UnmapViewOfFile(data_);
        }
        if (mapping_handle_ != nullptr) {
            CloseHandle(mapping_handle_);
        }
        if (file_handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(file_handle_);
        }
#else
        if (data_ != nullptr) {
            munmap(const_cast<char*>(data_), size_);
        }
        if (file_descriptor_ >= 0) {
            close(file_descriptor_);
        }
#endif
    }

    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;

    [[nodiscard]] bool isValid() const noexcept { return valid_; }
    [[nodiscard]] std::size_t size() const noexcept { return size_; }
    [[nodiscard]] std::string_view view() const noexcept {
        return data_ == nullptr ? std::string_view{} : std::string_view(data_, size_);
    }

private:
    const char* data_ = nullptr;
    std::size_t size_ = 0;
    bool valid_ = false;
#ifdef _WIN32
    HANDLE file_handle_ = INVALID_HANDLE_VALUE;
    HANDLE mapping_handle_ = nullptr;
#else
    int file_descriptor_ = -1;
#endif
};
