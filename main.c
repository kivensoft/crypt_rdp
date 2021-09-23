#include <wtypes.h>
#include <Wincrypt.h>
#include <windows.h>
#include <stdio.h>

static const char _HEX_TABLE[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

char* hex_to_asc(const BYTE *hex, size_t len) {
    char* r = (char*) malloc((len << 1) + 1);
    char* p = r;

	for (const BYTE *s = hex, *se = hex + len; s < se; s++) {
		*p++ = _HEX_TABLE[*s >> 4];
		*p++ = _HEX_TABLE[*s & 0x0F];
	}
    r[len << 1] = 0;

	return r;
}

char* protect_data(const wchar_t* lpszText, size_t len) {
	DATA_BLOB data_in;
	DATA_BLOB data_out;
	BYTE *pbDataInput = (BYTE *)lpszText;
	DWORD cbDataInput = len;

	data_in.pbData = pbDataInput;
	data_in.cbData = cbDataInput;

    char* r = NULL;
	if (CryptProtectData(&data_in, L"psw", NULL, NULL, NULL, 0, &data_out)) {
		r = hex_to_asc(data_out.pbData, data_out.cbData);
		LocalFree(data_out.pbData);
	}
	return r;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <password>\n", argv[0]);
        return -1;
    }

    char* pw = argv[1];
    size_t pw_len = strlen(pw);
    size_t wpw_len = MultiByteToWideChar(CP_ACP, 0, pw, pw_len, NULL, 0);
    wchar_t *wpw = (wchar_t*) malloc((wpw_len + 1) << 1);
    MultiByteToWideChar(CP_ACP, 0, pw, pw_len, wpw, wpw_len);
    wpw[wpw_len] = 0;
	char* enc = protect_data(wpw, wpw_len << 1);
    printf("username:s:administrator\n");
    printf("password 51:b:%s\n", enc);

    free(wpw);
    free(enc);
}