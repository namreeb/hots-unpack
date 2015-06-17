/*
    Copyright (c) 2015, namreeb (legal@namreeb.org)
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
    ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
    ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

    The views and conclusions contained in the software and documentation are those
    of the authors and should not be interpreted as representing official policies,
    either expressed or implied, of the FreeBSD Project.
*/

#include <iostream>
#include <string>
#include <vector>
#include <fstream>

#include <boost/program_options.hpp>

#include <hadesmem/process.hpp>
#include <hadesmem/find_pattern.hpp>
#include <hadesmem/pelib/pe_file.hpp>
#include <hadesmem/pelib/dos_header.hpp>
#include <hadesmem/pelib/nt_headers.hpp>
#include <hadesmem/pelib/section.hpp>
#include <hadesmem/pelib/section_list.hpp>

extern "C" {
#include "aes.h"
}

#include "offsets.hpp"

// this code is merely a c++ implementation of the Rust program published by athre0z @ ownedcore.com here:
// http://www.ownedcore.com/forums/heroes-of-storm/heroes-of-storm-exploits/519534-hots-unpack-removing-hots-binary-encryption-statically.html

struct ChunkEntry
{
    DWORD Offset;
    DWORD Size;
};

bool FindChunkTable(const std::vector<BYTE> &data, unsigned int &chunkTableOffset, unsigned int &chunkTableLength)
{
    for (unsigned int i = 0; i < data.size(); ++i)
    {
        unsigned int offset = 0, lastAddress = 0;

        // Check if candidate looks like a chunk table.
        while (i + offset + sizeof(ChunkEntry) < data.size())
        {
            const auto chunk = reinterpret_cast<const ChunkEntry *>(&data[i + offset]);

            // The chunk table's end is indicated with an 0xFFFFFFFF.
            if (offset >= 1000 * sizeof(ChunkEntry) && chunk->Offset == 0xFFFFFFFF)
            {
                chunkTableOffset = i;
                chunkTableLength = (offset / sizeof(ChunkEntry)) - 1;

                return true;
            }

            // The chunk table entries are stored ascending.
            if (chunk->Offset <= lastAddress)
                break;

            lastAddress = chunk->Offset;
            offset += sizeof(ChunkEntry);
        }
    }

    return false;
}

bool UnpackBinary(const std::string &inputFile, const std::string &outputFile)
{
    std::ifstream file(inputFile.c_str(), std::ios::binary);

    if (!file.good())
        return false;

    file.seekg(0, std::ios::end);
    DWORD fileSize = static_cast<DWORD>(file.tellg());
    file.seekg(0, std::ios::beg);

    std::vector<BYTE> fileContents(fileSize);
    file.read((char *)&fileContents[0], fileSize);
    file.close();

    const hadesmem::Process proc(::GetCurrentProcessId());
    const hadesmem::PeFile peFile(proc, &fileContents[0], hadesmem::PeFileType::Data, fileSize);

    try
    {
        const hadesmem::DosHeader dosHeader(proc, peFile);
        const hadesmem::NtHeaders ntHeaders(proc, peFile);

        const auto keyPtr = static_cast<PBYTE>(hadesmem::Find(proc, &fileContents[0], fileSize,
            L"0x68 0x80 0x00 0x00 0x00 "    // push 80h
            L"0x68 ?? ?? ?? ?? "            // push offset g_asesInputKey
            L"0x68 ?? ?? ?? ?? "            // push offset g_aesKey
            L"0xE8 ?? ?? ?? ?? "            // call AesSetDecryptKey
            L"0xE9",                        // jmp
            hadesmem::PatternFlags::kNone, 0)) + 6;

        const auto keyRva = *reinterpret_cast<PDWORD>(keyPtr)-ntHeaders.GetImageBase();

        std::cout << "AES key RVA: 0x" << std::hex << keyRva << std::endl;

        hadesmem::SectionList sections(proc, peFile);

        const auto keyFileOffset = RvaToFileOffset(static_cast<DWORD>(keyRva), sections);

        if (!keyFileOffset)
        {
            std::cerr << "Unable to find AES key RVA" << std::endl;
            return false;
        }

        BYTE key[16];
        memcpy(key, &fileContents[keyFileOffset], sizeof(key));

        std::cout << "AES key: " << std::hex;

        for (int i = 0; i < sizeof(key); ++i)
            std::cout << (unsigned int)key[i];

        std::cout << std::dec << std::endl;

        unsigned int chunkTableOffset, chunkTableLength;

        // scan for 'chunk table'
        if (!FindChunkTable(fileContents, chunkTableOffset, chunkTableLength))
        {
            std::cerr << "Unable to locate chunk table";
            return false;
        }

        std::cout << "Found chunk table at offset 0x" << std::hex << chunkTableOffset << " with " << std::dec << chunkTableLength << " entries" << std::endl;
        std::cout << "Assembling encrypted chunks..." << std::endl;
        
        // Collect all encrypted chunks into one buffer
        const auto chunks = reinterpret_cast<ChunkEntry *>(&fileContents[chunkTableOffset]);
        std::vector<BYTE> encryptedBuffer(fileSize);
        std::vector<DWORD> chunkFileOffsets(chunkTableLength);

        unsigned int currentOffset = 0;
        for (unsigned int i = 0, nextCompletion = 0; i < chunkTableLength; ++i)
        {
            if ((100 * i / chunkTableLength) >= nextCompletion)
            {
                std::cout << '\r' << nextCompletion << "% complete";
                std::cout.flush();

                nextCompletion++;
            }

            chunkFileOffsets[i] = RvaToFileOffset(chunks[i].Offset, sections);
            memcpy(&encryptedBuffer[currentOffset], &fileContents[chunkFileOffsets[i]], chunks[i].Size);
            currentOffset += chunks[i].Size;
        }

        std::cout << std::endl << "Finished." << std::endl;

        if (currentOffset % 16)
            encryptedBuffer.resize(currentOffset + 16 - (currentOffset % 16));

        std::vector<BYTE> decryptedBuffer(encryptedBuffer.size());

        std::cout << "Decrypting...";
        std::cout.flush();

        for (unsigned int i = 0; i < encryptedBuffer.size(); i += 16)
            AES128_ECB_decrypt(&encryptedBuffer[i], reinterpret_cast<const uint8_t *>(&key), &decryptedBuffer[i]);

        std::cout << " Finished." << std::endl;
        std::cout << "Inserting decrypted data back into binary..." << std::endl;

        for (unsigned int i = 0, readOffset = 0, nextCompletion = 0; i < chunkTableLength; ++i)
        {
            if ((100 * i / chunkTableLength) >= nextCompletion)
            {
                std::cout << '\r' << nextCompletion << "% complete";
                std::cout.flush();

                nextCompletion++;
            }

            memcpy(&fileContents[chunkFileOffsets[i]], &decryptedBuffer[readOffset], chunks[i].Size);
            readOffset += chunks[i].Size;
        }

        std::cout << std::endl << "Finished." << std::endl;

        // Blizz moved the IAT to the .reloc section, which isn't loaded by IDA
        // when loading a file without the "manual load" option, which results in
        // unresolved API calls. Rename it to make IDA map it into the IDB by default.
        for (auto &s : sections)
            if (s.GetName() == ".reloc")
            {
                s.SetName(".reloc_");
                s.UpdateWrite();
                std::cout << "Renamed .reloc to .reloc_" << std::endl;
            }

        std::cout << "Dumping new binary file to " << outputFile << std::endl;

        std::ofstream outFile(outputFile.c_str(), std::ios::binary);

        if (!outFile.good())
        {
            std::cerr << "Failed to open output file." << std::endl;
            return false;
        }

        outFile.write(reinterpret_cast<const char *>(&fileContents[0]), fileSize);
        outFile.close();
    }
    catch (std::exception const &e)
    {
        std::cerr << "Not a valid PE file" << std::endl;
        std::cerr << e.what() << std::endl;
        return false;
    }

    return true;
}

int main(int argc, char *argv[])
{
    std::string inputFile, outputFile;

    boost::program_options::options_description desc("Allowed options");
    desc.add_options()
        ("help,h", "display help message")
        ("input,i", boost::program_options::value<std::string>(&inputFile)->default_value("HeroesOfTheStorm.exe"), "input filename")
        ("output,o", boost::program_options::value<std::string>(&outputFile)->default_value("HeroesOfTheStormUnpacked.exe"), "output filename");

    boost::program_options::variables_map vm;

    try
    {
        boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);
        boost::program_options::notify(vm);

        if (vm.count("help"))
        {
            std::cout << desc << std::endl;
            return EXIT_SUCCESS;
        }
    }
    catch (boost::program_options::error const &e)
    {
        std::cerr << "ERROR: " << e.what() << std::endl << std::endl;
        std::cerr << desc << std::endl;
        return EXIT_FAILURE;
    }

    return UnpackBinary(inputFile, outputFile) ? EXIT_SUCCESS : EXIT_FAILURE;
}