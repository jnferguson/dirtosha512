/* 
	hacked up/works for me program to rename files in a series of directories based on their SHA512 sums 
	specifically makes processing files with tons of spaces or foreign characters a little easier.
*/


#include "stdafx.h"
#include <Windows.h>
#include <wincrypt.h>
#include <iostream>
#include <string>
#include <cstdlib>
#include <cstdint>
#include <vector>
#include <array>

#define REAL_MAX_PATH 32767

typedef std::basic_string< TCHAR > tstring_t;

typedef struct {
	tstring_t		path;
	tstring_t		name;
	DWORD			size;
} file_desc_t;

#define SHA512_LENGTH 64
typedef std::array< uint8_t, SHA512_LENGTH> sha512_t;


tstring_t
toHex(sha512_t& h)
{
	tstring_t d(L"0123456789ABCDEF");
	tstring_t r(L"");

	for (std::size_t idx = 0; idx < SHA512_LENGTH; idx++) {
		r += d.at(h.at(idx) >> 4);
		r += d.at(h.at(idx) & 0x0F);
	}

	return r;
}

tstring_t
getFileExtension(tstring_t& p)
{
	tstring_t::size_type idx = p.find_last_of(L".");
	tstring_t ret(L"");

	if (idx == tstring_t::npos)
		return tstring_t(L".unknown");

	return p.substr(idx);
}

tstring_t
lastErrorString(void)
{
	LPVOID		b(nullptr);
	tstring_t	r(L"");

	::FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr,
		::GetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&b,
		0, nullptr);

	r = reinterpret_cast< LPTSTR >(b);
	return r;
}

bool
read_file(file_desc_t& p, std::vector< uint8_t >& d)
{
	BYTE*		b(nullptr);
	DWORD		l(p.size);
	HANDLE		f(INVALID_HANDLE_VALUE);
	DWORD		c(0);
	DWORD		o(0);
	tstring_t	path(p.path + p.name);

	f = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);

	if (INVALID_HANDLE_VALUE == f) {
		std::wcerr << L"Error while calling ::CreateFile(): '" << path << L"': " << lastErrorString()  << std::endl;
		return false;
	}

	b = new BYTE[l+1];

	do {
		if (FALSE == ::ReadFile(f, b+o, l-o, &c, nullptr)) {
			std::wcerr << L"Error while calling ::ReadFile(): " << std::to_wstring(::GetLastError()) << std::endl;
			::CloseHandle(f);
			return false;
		}


		o += c;
	} while (1 == c);

	d.clear();
	d.resize(l);
	::memcpy_s(d.data(), d.size(), b, l);
	delete b;
	::CloseHandle(f);
	return true;
}

bool
rename_file(tstring_t& i, tstring_t& o)
{
	if (!i.compare(o))
		return true;

	
	::DeleteFileW(o.c_str());

	if (FALSE == ::MoveFileW(i.c_str(), o.c_str())) {
		std::wcerr << L"Failed to rename file: " << i << L" to " << o << L" : " << lastErrorString() << std::endl;
		return false;
	}

	return true;
}

bool
make_sha512(std::vector< uint8_t >& in, sha512_t& out)
{
	BYTE		hash[SHA512_LENGTH] = { 0 };
	HCRYPTPROV	hp					= NULL;
	HCRYPTHASH	ch					= NULL;
	DWORD		hl					= SHA512_LENGTH;

	if (UINT32_MAX <= in.size()) {
		std::wcerr << "Refusing to hash partial file (size > UINT32_MAX)" << std::endl;
		return false;
	}

	if (FALSE == ::CryptAcquireContext(&hp, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		std::wcerr << "Error while calling ::CryptAcquireContext(): " << lastErrorString() << std::endl;
		return false;
	}

	if (FALSE == ::CryptCreateHash(hp, CALG_SHA_512, 0, 0, &ch)) {
		std::wcerr << "Error while calling ::CryptCreateHash(): " << lastErrorString() << std::endl;
		::CryptReleaseContext(hp, 0);
		return false;
	}

	if (FALSE == ::CryptHashData(ch, in.data(), static_cast< DWORD >(in.size()), 0)) {
		std::wcerr << "Error while calling ::CryptHashData(): " << lastErrorString() << std::endl;
		::CryptDestroyHash(ch);
		::CryptReleaseContext(hp, 0);
		return false;
	}

	if (FALSE == ::CryptGetHashParam(ch, HP_HASHVAL, out.data(), &hl, 0)) {
		std::wcerr << "Error while calling ::CryptGetHashParam(): " << lastErrorString() << std::endl;
		::CryptDestroyHash(ch);
		::CryptReleaseContext(hp, 0);
		return false;
	}

	::CryptDestroyHash(ch);
	::CryptReleaseContext(hp, 0);
	return true;
}

bool 
find_files(tstring_t& p, std::vector< file_desc_t >& f)
{
	const tstring_t				sp(L"*");
	std::vector< file_desc_t >	files;
	file_desc_t					tmp;
	HANDLE						hnd(INVALID_HANDLE_VALUE);
	WIN32_FIND_DATA				fd = { 0 };

	hnd = ::FindFirstFile(tstring_t(p + L"\\" + sp).c_str(), &fd);

	if (INVALID_HANDLE_VALUE == hnd) {
		if (ERROR_FILE_NOT_FOUND != ::GetLastError()) {
			std::wcerr << L"Error while calling ::FindFirstFile(): " << lastErrorString() << std::endl;
			return false;
		} else
			return true;
	}

	do {
		if (! ::lstrcmpW(fd.cFileName, L".") || ! ::lstrcmp(fd.cFileName, L".."))
			continue;

		if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			if (false == find_files(tstring_t(p + L"\\" + fd.cFileName), files))
				return false;

		} else {
			tmp.path	= tstring_t(p + L"\\");
			tmp.size	= fd.nFileSizeLow;
			tmp.name	= fd.cFileName; 
			files.push_back(tmp);
		}
	} while (::FindNextFile(hnd, &fd));

	::FindClose(hnd);

	f.insert(f.end(), files.begin(), files.end());

	return true;

}

signed int 
_tmain(signed int ac, _TCHAR** av)
{
	std::vector< file_desc_t >	files;
	std::vector< tstring_t >	dirs;
	tstring_t					opath(L""); 
	tstring_t					ipath(L"");

	if (2 > ac) {
		std::wcerr << "Usage " << av[0] << L" <input directory>" << std::endl;
		return EXIT_FAILURE;
	}

	for (signed int idx = 1; idx < ac; idx++) {
		tstring_t str(av[idx]);

		while (L'\\' == str.back() || L'/' == str.back())
			str.pop_back();

		if (!str.size())
			continue;

		dirs.push_back(str);
	}

	for (auto& d : dirs) {
		TCHAR		b[REAL_MAX_PATH + 1] = { 0 };
		DWORD		r = ::GetFullPathName(d.c_str(), REAL_MAX_PATH, &b[0], nullptr);
		tstring_t	p(L"\\\\?\\");

		if (0 == r || r > REAL_MAX_PATH) {
			std::wcerr << "Error while calling ::GetFullPathName() for parameter '" << d << L"': " << lastErrorString() << std::endl;
			return EXIT_FAILURE;
		}

		p += b;

		r = ::GetFileAttributes(p.c_str());

		if (INVALID_FILE_ATTRIBUTES == r) {
			std::wcerr << "Failed while calling ::GetFileAttributes() for file: '" << d << L"': " << lastErrorString() << std::endl;
			return EXIT_FAILURE;
		}

		if (r & FILE_ATTRIBUTE_DIRECTORY) {
			if (false == find_files(p, files))
				return EXIT_FAILURE;
		}
	}

	for (auto& f : files) {
		sha512_t				tmp;
		std::vector< uint8_t >	in;

		if (false == read_file(f, in))
			return EXIT_FAILURE;

		if (false == make_sha512(in, tmp))
			return EXIT_FAILURE;

		ipath = f.path + f.name;
		opath = f.path;
		opath += toHex(tmp);
		opath += getFileExtension(f.name);
		std::wcout << L".";
		std::wcout.flush();

		if (false == rename_file(ipath, opath))
			return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

