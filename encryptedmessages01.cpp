#include "stdafx.h"
#include "EncryptedMessages01.h"
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>
#include <objidl.h>
#include <gdiplus.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <windows.h>
#include <direct.h>
#include <stdio.h>
#include <Winuser.h>
#include <Windows.h>
#include <strsafe.h>
#include <sstream>
#include <fstream>
#include <codecvt>
#include <atlconv.h>
#include "..\..\crypto\sha.h"
#include "..\..\crypto\rsa.h"
#include "..\..\crypto\files.h"
#include "..\..\crypto\hex.h"
#include "..\..\crypto\modes.h"
#include "..\..\crypto\osrng.h"
#include "..\..\crypto\cryptlib.h"
#include "..\..\crypto\integer.h"
#include "..\..\crypto\nbtheory.h"
#include "..\..\crypto\base64.h"
#include "..\..\crypto\xed25519.h"
#include "..\..\crypto\dh2.h"
#include "..\..\crypto\cmac.h"
#include "..\..\crypto\hmac.h"
#include "..\..\crypto\gcm.h"
#include "..\..\crypto\filters.h"
#include "..\..\crypto\hkdf.h"
#include "..\..\crypto\iterhash.h"

#pragma comment (lib, "Gdiplus.lib")

using namespace std;
using namespace Gdiplus;
using namespace CryptoPP;

#define MAX_LOADSTRING 100

HINSTANCE hInst;								
TCHAR szTitle[MAX_LOADSTRING] = _T("Šifrovanie správ");
TCHAR szWindowClass[MAX_LOADSTRING] = _T("win32app");
TCHAR text01[] = _T("Testovanie 01.");

HWND hWnd;
HWND edit[32];
HWND list;
HWND hButton[64];
HWND hEncrypt, hDecrypt;
HWND hStatic[16];
HWND hText[32];
HWND hDialog;
HWND hwndGoto = NULL, hHeslo = NULL, hNoveHeslo = NULL, hNoveMeno = NULL, hZmenaHesla = NULL;
HWND uvodne_heslo, h_ecdh_verejny_kluc, h_ecdh_kluc_kontaktu, h_meno_kontaktu, h_heslo1, h_heslo2, h_povodne_heslo, h_nove_meno;

HMENU hMenubar, hFile, hOptions;
HFONT typ_pisma_pole, typ_pisma_tlacitko, typ_pisma_nadpis;

int iLine;
BOOL fRelative; 

PAINTSTRUCT ps;
HDC hdc;
HBRUSH brush;
RECT r;
RECT okno = {0, 0, 100, 100};

FILE *f1;

ATOM				MyRegisterClass(HINSTANCE hInstance);
BOOL				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	About(HWND, UINT, WPARAM, LPARAM);

WNDPROC vykonanie;
WNDPROC vykonanie_okno;

string zasifrovany_udaj[32], udaj[32], udaj_byty[32], udaj_meno[32], udaj_heslo, udaj_heslo_base64;
wstring meno_kontaktu;
wstring udaj_w[32];
//codecvt_utf8<wstring> udaj_w[32];
wchar_t ecdh_kluc_kontaktu_w[65] = { NULL };

char priecinok[MAX_PATH];
unsigned char vygenerovany_sukromny_kluc[32];
unsigned int cislo_tlacitka = 0;
unsigned int pocet_riadkov = 0;
bool kontrola = false;

LPCWSTR vysledny_retazec;
LPWSTR heslo_z_okna;

unsigned char salt_key[] = { 0x0, 0x30, 0x31, 0x30, 0xd, 0x6, 0x9, 0x60, 0x86, 0x48, 0x1, 0x65, 0x3, 0x4, 0x2, 0x1 };
unsigned char salt_iv[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
unsigned char salt_hmac[] = { 0xd, 0x6, 0x9, 0x60, 0x86, 0x48, 0x1, 0x65, 0x3, 0x4, 0x2, 0x1, 0x5, 0x0, 0x4, 0x20 };

unsigned char hlavny_kluc[32];
unsigned char hlavny_kluc_iv[16];

//int iteracia = 0;

wstring transformacia_retazca(const string& s)
{
    int len;
    int slength = (int)s.length() + 1;
    len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
    wchar_t* buf = new wchar_t[len];
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
    wstring r(buf);
    delete[] buf;
    return r;
}

string konvertacia_na_retazec(const CryptoPP::Integer& n)
{
    ostringstream os;
    os << hex << n;
    return os.str();
}

int nespravne_heslo()
{
    int msgboxID = MessageBox(NULL, L"Nesprávne heslo.\nProgram sa ukonèí.", L"Nesprávne heslo", MB_ICONSTOP | MB_OK);

    return msgboxID;    
}

int vymazanie_kontaktu()
{
    int msgboxID = MessageBox(NULL, L"Naozaj si želáte vymaza\nzvolený kontakt?", L"Vymazanie zvoleného kontaktu", MB_ICONEXCLAMATION | MB_YESNO);

    if (msgboxID == IDYES)
    {
        
		FILE *subor;
		subor = fopen("data.txt", "w");

		for (int i = 0; i < pocet_riadkov; i++)
		{ 
			
			if (zasifrovany_udaj[i].length() > 3 && i != cislo_tlacitka) { fprintf(subor, "%s\n", &zasifrovany_udaj[i][0]); }

		}

		fclose(subor);

		for (int i = 0; i < udaj_byty[cislo_tlacitka].length(); i++) { udaj_byty[cislo_tlacitka][i] = NULL; }
		for (int i = 0; i < zasifrovany_udaj[cislo_tlacitka].length(); i++) { zasifrovany_udaj[cislo_tlacitka][i] = NULL; }

		DestroyWindow(hButton[cislo_tlacitka]);
		SendMessage(hStatic[2], WM_SETTEXT, 0, (LPARAM)L"Nie je zvolený žiadny kontakt.");
		cislo_tlacitka = 0;

    }

    return msgboxID;    
}

LRESULT CALLBACK ButtonProc01(HWND tlacitko, UINT message, WPARAM wp, LPARAM lp)
{
    switch (message) {
    case WM_LBUTTONDOWN:
        break;
    case WM_LBUTTONUP:
		InvalidateRect(hWnd, NULL, TRUE);
		UpdateWindow(hWnd);

		SendMessage(hWnd, WM_COMMAND, LOWORD(wp), NULL);

        break;
    }

    return CallWindowProc(vykonanie, tlacitko, message, wp, lp);
}

BOOL CALLBACK GoToProc(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam) 
{ 
	AutoSeededRandomPool ecdh_rnd;
	x25519 ecdh1;
	Base64Encoder zakodovanie;

	string ecdh_verejny_kluc_string, ecdh_zdielany_kluc_string, ecdh_zdielany_iv_string, ecdh_zdielany_hmac_kluc_string;

	h_ecdh_verejny_kluc = GetDlgItem(hwndGoto, IDC_EDIT1);
	h_ecdh_kluc_kontaktu = GetDlgItem(hwndGoto, IDC_EDIT2);
	h_meno_kontaktu = GetDlgItem(hwndGoto, IDC_EDIT3);

	SecByteBlock ecdh_sukromny_kluc(x25519::SECRET_KEYLENGTH);
	SecByteBlock ecdh_verejny_kluc(x25519::PUBLIC_KEYLENGTH);

    switch (message)
    {
        case WM_INITDIALOG:
            return TRUE;
 
        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
				case IDC_BUTTON1:
				{
					
					ecdh1.GeneratePrivateKey(ecdh_rnd, ecdh_sukromny_kluc);
					ecdh1.GeneratePublicKey(ecdh_rnd, ecdh_sukromny_kluc, ecdh_verejny_kluc);

					for (int i = 0; i < 32; i++) { vygenerovany_sukromny_kluc[i] = ecdh_sukromny_kluc[i]; }

					HexEncoder encoder_kluc;
					encoder_kluc.Put(ecdh_verejny_kluc, ecdh_verejny_kluc.size());
					encoder_kluc.MessageEnd();
					word64 size = encoder_kluc.MaxRetrievable();
					if (size && size <= SIZE_MAX) { ecdh_verejny_kluc_string.resize(size); encoder_kluc.Get((unsigned char*)&ecdh_verejny_kluc_string[0], ecdh_verejny_kluc_string.size()); }

					int dlzka = ecdh_verejny_kluc_string.length();
					wchar_t* buffer = new wchar_t[dlzka + 1];
					for (int i = 0; i <= dlzka; i++) { buffer[i] = NULL; }
					for (int i = 0; i < dlzka; i++) { buffer[i] = ecdh_verejny_kluc_string[i]; }

					SendMessage(h_ecdh_verejny_kluc, WM_SETTEXT, (WPARAM)_tcslen(buffer), (LPARAM)buffer);

					delete [] buffer; buffer = NULL;

				break;
				}
			
				case IDOK: 
				{
					
					int dlzka_kluc_kontaktu = SendMessage(h_ecdh_kluc_kontaktu, WM_GETTEXTLENGTH, 0, 0);
					wchar_t* buffer_kluc = new wchar_t[dlzka_kluc_kontaktu + 1];
					SendMessage(h_ecdh_kluc_kontaktu, WM_GETTEXT, (WPARAM)dlzka_kluc_kontaktu + 1, (LPARAM)buffer_kluc);

					unsigned char ecdh_kluc_kontaktu_char[64] = { NULL };

					if (dlzka_kluc_kontaktu >= 64)
					{
					
						for (int i = 0; i < 64; i++) { ecdh_kluc_kontaktu_char[i] = buffer_kluc[i]; }

					}

					int dlzka_meno = SendMessage(h_meno_kontaktu, WM_GETTEXTLENGTH, 0, 0);
					wchar_t* buffer_meno = new wchar_t[dlzka_meno + 1];
					SendMessage(h_meno_kontaktu, WM_GETTEXT, (WPARAM)dlzka_meno + 1, (LPARAM)buffer_meno);

					wstring medziretazec(buffer_meno);
					//string meno(medziretazec.begin(), medziretazec.end());
					wstring_convert<codecvt_utf8<wchar_t>> konvertovanie_na_utf8;
					string meno = konvertovanie_na_utf8.to_bytes(medziretazec);
					meno.append(1, (char)0xff);
					
					SecByteBlock ecdh_kluc_kontaktu(ecdh1.AgreedValueLength());

					kontrola = false;

					for (int i = 0; i < sizeof(ecdh_kluc_kontaktu_char); i++)
					{
				
						if ((ecdh_kluc_kontaktu_char[i] >= 0x30 && ecdh_kluc_kontaktu_char[i] <= 0x39) || (ecdh_kluc_kontaktu_char[i] >= 0x41 && ecdh_kluc_kontaktu_char[i] <= 0x46)) { kontrola = true; }
						else
						{
					
							kontrola = false;
							int msgboxID = MessageBox(NULL, L"Nevložili ste verejný k¾úè\nkontaktu v platnom formáte.", L"Nesprávny formát verejného k¾úèa", MB_ICONEXCLAMATION | MB_OK);
							break;
					
						}
				
					}

					if (kontrola == true)
					{

						HexDecoder decoder;
						decoder.Put((unsigned char*)ecdh_kluc_kontaktu_char, sizeof(ecdh_kluc_kontaktu_char));
						decoder.MessageEnd();

						word64 size = decoder.MaxRetrievable();
						if(size && size <= SIZE_MAX) { decoder.Get(ecdh_kluc_kontaktu, ecdh_kluc_kontaktu.size()); }

						SecByteBlock master_secret(ecdh1.AgreedValueLength());
						if(!ecdh1.Agree(master_secret, vygenerovany_sukromny_kluc, ecdh_kluc_kontaktu)) { throw runtime_error("Nepodarilo sa vypocitat zdielany kluc (1)."); }

						unsigned char spolocny_kluc[32];
						unsigned char spolocny_iv[16];
						unsigned char spolocny_hmac_kluc[32];

						string na_zapis_kluce, na_zapis, na_zapis_base64, na_zapis_zasifrovane;
						na_zapis_kluce.resize(80);

						HKDF<SHA256> hkdf;
						hkdf.DeriveKey(spolocny_kluc, sizeof(spolocny_kluc), master_secret, master_secret.size(), salt_key, sizeof(salt_key), NULL, NULL);
						hkdf.DeriveKey(spolocny_iv, sizeof(spolocny_iv), master_secret, master_secret.size(), salt_iv, sizeof(salt_iv), NULL, NULL);
						hkdf.DeriveKey(spolocny_hmac_kluc, sizeof(spolocny_hmac_kluc), master_secret, master_secret.size(), salt_hmac, sizeof(salt_hmac), NULL, NULL);

						for (int i = 0; i < 32; i++) { na_zapis_kluce[i] = spolocny_kluc[i]; }
						for (int i = 0; i < 16; i++) { na_zapis_kluce[i + 32] = spolocny_iv[i]; }
						for (int i = 0; i < 32; i++) { na_zapis_kluce[i + 48] = spolocny_hmac_kluc[i]; }

						na_zapis = meno + na_zapis_kluce;
							
						CBC_Mode<AES>::Encryption zasifrovanie;
						zasifrovanie.SetKeyWithIV(hlavny_kluc, sizeof(hlavny_kluc), hlavny_kluc_iv);
						StringSource(na_zapis, true, new StreamTransformationFilter(zasifrovanie, new StringSink(na_zapis_zasifrovane), BlockPaddingSchemeDef::PKCS_PADDING));

						zakodovanie.Attach(new StringSink(na_zapis_base64));
						zakodovanie.Put((unsigned char*)na_zapis_zasifrovane.data(), na_zapis_zasifrovane.size());
						zakodovanie.MessageEnd();
						size = zakodovanie.MaxRetrievable();
						if (size && size <= SIZE_MAX) { na_zapis_base64.resize(size); zakodovanie.Get((unsigned char*)&na_zapis_base64[0], na_zapis_base64.size()); }
						zakodovanie.Detach(new StringSink(na_zapis_base64));

						string cast[32], do_suboru;

						string rozdelovac = "\n";
						int dlzka = 0, z = 0;
						size_t pozicia = 0;

						while ((pozicia = na_zapis_base64.find(rozdelovac)) != string::npos)
						{
		
							cast[z] = na_zapis_base64.substr(0, pozicia);
    						na_zapis_base64.erase(0, pozicia + rozdelovac.length());
							z++;

						}

						cast[z] = na_zapis_base64.substr(0, pozicia);

						for (int j = 0; j <= z; j++)
						{

							do_suboru.append(cast[j]);
	
						}

						FILE *subor;
						subor = fopen("data.txt", "w");
						for (int i = 0; i < pocet_riadkov; i++) { if (zasifrovany_udaj[i].length() > 3) { fprintf(subor, "%s\n", &zasifrovany_udaj[i][0]); } }
						zasifrovany_udaj[pocet_riadkov] = do_suboru;
						fprintf(subor, "%s", &do_suboru[0]);
						fclose(subor);

						udaj_w[pocet_riadkov] = buffer_meno;
						udaj_byty[pocet_riadkov].resize(80);

						wstring_convert<codecvt_utf8<wchar_t>> konvertovanie_na_utf8;
						udaj_meno[pocet_riadkov]  = konvertovanie_na_utf8.to_bytes(udaj_w[pocet_riadkov]);

						for (int i = 0; i < 80; i++) { udaj_byty[pocet_riadkov][i] = na_zapis_kluce[i]; }

						SendMessage(hWnd, WM_COMMAND, (WPARAM)601, (LPARAM)buffer_meno);

					}

					delete [] buffer_meno; buffer_meno = NULL;
					delete [] buffer_kluc; buffer_kluc = NULL;

					DestroyWindow(hwndGoto);
                    hwndGoto = NULL;
                    return TRUE;
				break;
				}
 
                case IDCANCEL:
                    DestroyWindow(hwndGoto);
                    hwndGoto = NULL;
                    return TRUE;
				break;
            } 
    }

    return FALSE; 
}

BOOL CALLBACK PasswordProc(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam) 
{ 
	string riadok, digest_hesla;
	int i = 0, j = 0;

	pocet_riadkov = 0;

	uvodne_heslo = GetDlgItem(hHeslo, IDC_EDIT1);

	word64 size;

	Base64Decoder odkodovanie_kontaktov;
 
    switch (message) 
    { 
        case WM_INITDIALOG:
            return TRUE;
 
        case WM_COMMAND: 
            switch (LOWORD(wParam)) 
            { 
							
				case IDOK2:
				{
					int dlzka = SendMessage(uvodne_heslo, WM_GETTEXTLENGTH, 0, 0);
					wchar_t* buffer = new wchar_t[dlzka + 1];
					SendMessage(uvodne_heslo, WM_GETTEXT, (WPARAM)dlzka + 1, (LPARAM)buffer);

					DestroyWindow(hHeslo);
                    hHeslo = NULL;

					ifstream subor_heslo("password.txt");
					
					wstring_convert<codecvt_utf8<wchar_t>> konvertovanie_z_utf8;

					if (subor_heslo.is_open())
					{

						if (subor_heslo.good()) { getline(subor_heslo, udaj_heslo_base64); }
						subor_heslo.close();

						odkodovanie_kontaktov.Attach(new StringSink(udaj_heslo));
						odkodovanie_kontaktov.Put((unsigned char*)udaj_heslo_base64.data(), udaj_heslo_base64.size());
						odkodovanie_kontaktov.MessageEnd();
						size = odkodovanie_kontaktov.MaxRetrievable();
						if (size && size <= SIZE_MAX) { udaj_heslo.resize(size); odkodovanie_kontaktov.Get((unsigned char*)&udaj_heslo[0], udaj_heslo.size()); }
						odkodovanie_kontaktov.Detach(new StringSink(udaj_heslo));

						wstring medziretazec(buffer);
						string heslo(medziretazec.begin(), medziretazec.end());

						SHA256 hash_hesla;
						hash_hesla.Update((const unsigned char*)heslo.data(), heslo.size());
						digest_hesla.resize(hash_hesla.DigestSize());
						hash_hesla.Final((unsigned char*)&digest_hesla[0]);

						HKDF<SHA256> hkdf_heslo;
						hkdf_heslo.DeriveKey(hlavny_kluc, sizeof(hlavny_kluc), (unsigned char*)heslo.data(), heslo.length(), salt_key, sizeof(salt_key), NULL, NULL);
						hkdf_heslo.DeriveKey(hlavny_kluc_iv, sizeof(hlavny_kluc_iv), (unsigned char*)heslo.data(), heslo.length(), salt_iv, sizeof(salt_iv), NULL, NULL);

						ifstream subor("data.txt");
    
						if (subor.is_open())
						{

							while (subor.good() && i < 32)
							{

								getline(subor, zasifrovany_udaj[i]);
								if (zasifrovany_udaj[i].length() > 3) { pocet_riadkov++; }
								i++;

							}

							subor.close();

						}

						if (pocet_riadkov > 0)
						{

							char rozdelovac = 0xff;
							size_t pozicia = 0;

							if (digest_hesla.compare(udaj_heslo) == 0)
							{
							
								for (int j = 0; j < pocet_riadkov; j++)
								{

									if (zasifrovany_udaj[j].length() > 3)
									{

										odkodovanie_kontaktov.Attach(new StringSink(udaj[j]));
										odkodovanie_kontaktov.Put((unsigned char*)zasifrovany_udaj[j/* + 1*/].data(), zasifrovany_udaj[j/* + 1*/].size());
										odkodovanie_kontaktov.MessageEnd();
										size = odkodovanie_kontaktov.MaxRetrievable();
										if (size && size <= SIZE_MAX) { udaj[j].resize(size); odkodovanie_kontaktov.Get((unsigned char*)&udaj[j][0], udaj[j].size()); }
										odkodovanie_kontaktov.Detach(new StringSink(udaj[j]));
									
										CBC_Mode<AES>::Decryption odsifrovanie;
										odsifrovanie.SetKeyWithIV(hlavny_kluc, sizeof(hlavny_kluc), hlavny_kluc_iv);
										StringSource(udaj[j], true, new StreamTransformationFilter(odsifrovanie, new StringSink(udaj_byty[j]), BlockPaddingSchemeDef::PKCS_PADDING));

										pozicia = udaj_byty[j].find(rozdelovac);
										udaj_meno[j] = udaj_byty[j].substr(0, pozicia);
										udaj_byty[j].erase(0, pozicia + 1);

										udaj_w[j] = konvertovanie_z_utf8.from_bytes(udaj_meno[j]);

										hButton[j] = CreateWindow(L"Button", udaj_w[j].c_str(), WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0 + (40 * j), 160, 40, hWnd, (HMENU)(1001 + j), hInst, NULL);
										SendMessage(hButton[j], WM_SETFONT, WPARAM(typ_pisma_tlacitko), TRUE);
										vykonanie = (WNDPROC)SetWindowLong(hButton[j], GWL_WNDPROC, (LONG)ButtonProc01);

									}

								}

							}
							else
							{
							
								nespravne_heslo();
								DestroyWindow(hWnd);
						
							}

						}

					}

					delete [] buffer; buffer = NULL;

                    return TRUE;	
				break;
				}
 
                case IDCANCEL2:
                    DestroyWindow(hwndDlg);
                    hHeslo = NULL;
					PostQuitMessage(0);
                    return TRUE;
				break;
            } 
    }

    return FALSE; 
}

BOOL CALLBACK nove_heslo(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam) 
{
	h_heslo1 = GetDlgItem(hNoveHeslo, IDC_EDIT1);
	h_heslo2 = GetDlgItem(hNoveHeslo, IDC_EDIT4);

	unsigned char digest_hesla[32];

	string digest_hesla_base64;

	switch (message) 
    { 
        case WM_INITDIALOG: 
            return TRUE; 
 
        case WM_COMMAND: 
            switch (LOWORD(wParam)) 
            {

			case IDOK3:
			{
				int dlzka_heslo1 = SendMessage(h_heslo1, WM_GETTEXTLENGTH, 0, 0);
				wchar_t* buffer_heslo1 = new wchar_t[dlzka_heslo1 + 1];
				SendMessage(h_heslo1, WM_GETTEXT, (WPARAM)dlzka_heslo1 + 1, (LPARAM)buffer_heslo1);

				wstring medziretazec_heslo1(buffer_heslo1);
				string heslo1(medziretazec_heslo1.begin(), medziretazec_heslo1.end());

				int dlzka_heslo2 = SendMessage(h_heslo2, WM_GETTEXTLENGTH, 0, 0);
				wchar_t* buffer_heslo2 = new wchar_t[dlzka_heslo2 + 1];
				SendMessage(h_heslo2, WM_GETTEXT, (WPARAM)dlzka_heslo2 + 1, (LPARAM)buffer_heslo2);

				wstring medziretazec_heslo2(buffer_heslo2);
				string heslo2(medziretazec_heslo2.begin(), medziretazec_heslo2.end());

				if (heslo1.compare(heslo2) == 0)
				{

					SHA256 hash_hesla;
					hash_hesla.Update((const unsigned char*)heslo1.data(), heslo1.size());
					hash_hesla.Final(digest_hesla);

					Base64Encoder encoder_heslo;
					encoder_heslo.Put(digest_hesla, sizeof(digest_hesla));
					encoder_heslo.MessageEnd();
					word64 size = encoder_heslo.MaxRetrievable();
					if (size && size <= SIZE_MAX) { digest_hesla_base64.resize(size); encoder_heslo.Get((unsigned char*)&digest_hesla_base64[0], digest_hesla_base64.size()); }

					FILE *subor;
					subor = fopen("password.txt", "w");
					fprintf(subor, "%s", &digest_hesla_base64[0]);
					fclose(subor);

					HKDF<SHA256> hkdf;
					hkdf.DeriveKey(hlavny_kluc, sizeof(hlavny_kluc), (unsigned char*)heslo1.data(), heslo1.length(), salt_key, sizeof(salt_key), NULL, NULL);
					hkdf.DeriveKey(hlavny_kluc_iv, sizeof(hlavny_kluc_iv), (unsigned char*)heslo1.data(), heslo1.length(), salt_iv, sizeof(salt_iv), NULL, NULL);

					int msgboxID = MessageBox(NULL, L"Hlavné heslo bolo\núspešne vytvorené.", L"Hlavné heslo", MB_ICONINFORMATION | MB_OK);

					DestroyWindow(hNoveHeslo);
					hNoveHeslo = NULL;

				}
				else
				{
				
					int msgboxID = MessageBox(NULL, L"Heslá nie sú rovnaké.\nProsím vložte rovnaké heslo.", L"Chybné heslo", MB_ICONEXCLAMATION | MB_OK);
				
				}

				delete [] buffer_heslo1; buffer_heslo1 = NULL;
				delete [] buffer_heslo2; buffer_heslo2 = NULL;

				return TRUE;
			break;
			}

			case IDCANCEL3:
                DestroyWindow(hNoveHeslo);
                hNoveHeslo = NULL;
				PostQuitMessage(0);
                return TRUE;
			break;

			default:
				return TRUE;
			break;

			}

	}

	return FALSE;
}

BOOL CALLBACK nove_meno(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam) 
{
	string na_zapis, na_zapis_zasifrovane, na_zapis_base64, cast[32], do_suboru;
	h_nove_meno = GetDlgItem(hNoveMeno, IDC_EDIT1);

	Base64Encoder zakodovanie;

	switch (message) 
    {
        case WM_INITDIALOG: 
            return TRUE;
 
        case WM_COMMAND:
            switch (LOWORD(wParam)) 
            {
				case IDOK4:
				{
					int dlzka_meno = SendMessage(h_nove_meno, WM_GETTEXTLENGTH, 0, 0);
					wchar_t* buffer_meno = new wchar_t[dlzka_meno + 1];
					SendMessage(h_nove_meno, WM_GETTEXT, (WPARAM)dlzka_meno + 1, (LPARAM)buffer_meno);

					wstring medziretazec(buffer_meno);
					wstring_convert<codecvt_utf8<wchar_t>> konvertovanie_na_utf8;
					string meno = konvertovanie_na_utf8.to_bytes(medziretazec);
					meno.append(1, (char)0xff);

					na_zapis = meno + udaj_byty[cislo_tlacitka];

					CBC_Mode<AES>::Encryption zasifrovanie;
					zasifrovanie.SetKeyWithIV(hlavny_kluc, sizeof(hlavny_kluc), hlavny_kluc_iv);
					StringSource(na_zapis, true, new StreamTransformationFilter(zasifrovanie, new StringSink(na_zapis_zasifrovane), BlockPaddingSchemeDef::PKCS_PADDING));

					zakodovanie.Attach(new StringSink(na_zapis_base64));
					zakodovanie.Put((unsigned char*)na_zapis_zasifrovane.data(), na_zapis_zasifrovane.size());
					zakodovanie.MessageEnd();
					word64 size = zakodovanie.MaxRetrievable();
					if (size && size <= SIZE_MAX) { na_zapis_base64.resize(size); zakodovanie.Get((unsigned char*)&na_zapis_base64[0], na_zapis_base64.size()); }
					zakodovanie.Detach(new StringSink(na_zapis_base64));

					string rozdelovac = "\n";
					int z = 0;
					size_t pozicia = 0;

					while ((pozicia = na_zapis_base64.find(rozdelovac)) != string::npos)
					{
		
						cast[z] = na_zapis_base64.substr(0, pozicia);
    					na_zapis_base64.erase(0, pozicia + rozdelovac.length());
						z++;

					}

					cast[z] = na_zapis_base64.substr(0, pozicia);

					zasifrovany_udaj[cislo_tlacitka].clear();
					//for (int i = 0; i < zasifrovany_udaj[cislo_tlacitka].length(); i++) { zasifrovany_udaj[pocet_riadkov][i] = NULL; }

					for (int j = 0; j <= z; j++)
					{

						zasifrovany_udaj[cislo_tlacitka].append(cast[j]);
	
					}

					FILE *subor;
					subor = fopen("data.txt", "w");
					for (int i = 0; i < pocet_riadkov; i++) { if (zasifrovany_udaj[i].length() > 3) { fprintf(subor, "%s\n", &zasifrovany_udaj[i][0]); } }
					fclose(subor);

					udaj_w[cislo_tlacitka] = buffer_meno;
					meno_kontaktu = L"Zvolený kontakt: " + udaj_w[cislo_tlacitka];

					udaj_meno[cislo_tlacitka]  = konvertovanie_na_utf8.to_bytes(udaj_w[cislo_tlacitka]);

					SendMessage(hButton[cislo_tlacitka], WM_SETTEXT, (WPARAM)_tcslen(buffer_meno), (LPARAM)buffer_meno);
					SendMessage(hStatic[2], WM_SETTEXT, (WPARAM)_tcslen(meno_kontaktu.c_str()), (LPARAM)meno_kontaktu.c_str());

					DestroyWindow(hNoveMeno);
					hNoveMeno = NULL;

					delete [] buffer_meno; buffer_meno = NULL;

					return TRUE;
				break;
				}

				case IDCANCEL4:
					DestroyWindow(hNoveMeno);
					hNoveMeno = NULL;
					return TRUE;
				break;

				default:
					return TRUE;
				break;	
				
			}
	}

	return FALSE;
}

BOOL CALLBACK zmena_hesla(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam) 
{
	h_povodne_heslo = GetDlgItem(hZmenaHesla, IDC_EDIT3);
	h_heslo1 = GetDlgItem(hZmenaHesla, IDC_EDIT1);
	h_heslo2 = GetDlgItem(hZmenaHesla, IDC_EDIT4);

	string digest_povodneho_hesla, digest_hesla_base64;
	string novy_riadok[32], na_zapis_base64[32], cast[32];
	unsigned char digest_hesla[32];

	int z, riadok = 0;
	size_t pozicia;

	Base64Encoder zakodovanie;

	switch (message) 
    {
        case WM_INITDIALOG: 
            return TRUE;
 
        case WM_COMMAND:
            switch (LOWORD(wParam)) 
            {
				case IDOK5:
				{
					int dlzka_povodne_heslo = SendMessage(h_povodne_heslo, WM_GETTEXTLENGTH, 0, 0);
					wchar_t* buffer_povodne_heslo = new wchar_t[dlzka_povodne_heslo + 1];
					SendMessage(h_povodne_heslo, WM_GETTEXT, (WPARAM)dlzka_povodne_heslo + 1, (LPARAM)buffer_povodne_heslo);

					wstring medziretazec_povodne_heslo(buffer_povodne_heslo);
					string povodne_heslo(medziretazec_povodne_heslo.begin(), medziretazec_povodne_heslo.end());

					int dlzka_heslo1 = SendMessage(h_heslo1, WM_GETTEXTLENGTH, 0, 0);
					wchar_t* buffer_heslo1 = new wchar_t[dlzka_heslo1 + 1];
					SendMessage(h_heslo1, WM_GETTEXT, (WPARAM)dlzka_heslo1 + 1, (LPARAM)buffer_heslo1);

					wstring medziretazec_heslo1(buffer_heslo1);
					string heslo1(medziretazec_heslo1.begin(), medziretazec_heslo1.end());

					int dlzka_heslo2 = SendMessage(h_heslo2, WM_GETTEXTLENGTH, 0, 0);
					wchar_t* buffer_heslo2 = new wchar_t[dlzka_heslo2 + 1];
					SendMessage(h_heslo2, WM_GETTEXT, (WPARAM)dlzka_heslo2 + 1, (LPARAM)buffer_heslo2);

					wstring medziretazec_heslo2(buffer_heslo2);
					string heslo2(medziretazec_heslo2.begin(), medziretazec_heslo2.end());

					SHA256 hash_povodneho_hesla;
					hash_povodneho_hesla.Update((const unsigned char*)povodne_heslo.data(), povodne_heslo.size());
					digest_povodneho_hesla.resize(hash_povodneho_hesla.DigestSize());
					hash_povodneho_hesla.Final((unsigned char*)&digest_povodneho_hesla[0]);

					if (digest_povodneho_hesla.compare(udaj_heslo) == 0)
					{

						if (heslo1.compare(heslo2) == 0)
						{

							SHA256 hash_hesla;
							hash_hesla.Update((const unsigned char*)heslo1.data(), heslo1.size());
							hash_hesla.Final(digest_hesla);

							Base64Encoder encoder_heslo;
							encoder_heslo.Put(digest_hesla, sizeof(digest_hesla));
							encoder_heslo.MessageEnd();
							word64 size = encoder_heslo.MaxRetrievable();
							if (size && size <= SIZE_MAX) { digest_hesla_base64.resize(size); encoder_heslo.Get((unsigned char*)&digest_hesla_base64[0], digest_hesla_base64.size()); }

							FILE *subor;
							subor = fopen("password.txt", "w");
							fprintf(subor, "%s", &digest_hesla_base64[0]);
							fclose(subor);

							HKDF<SHA256> hkdf;
							hkdf.DeriveKey(hlavny_kluc, sizeof(hlavny_kluc), (unsigned char*)heslo1.data(), heslo1.length(), salt_key, sizeof(salt_key), NULL, NULL);
							hkdf.DeriveKey(hlavny_kluc_iv, sizeof(hlavny_kluc_iv), (unsigned char*)heslo1.data(), heslo1.length(), salt_iv, sizeof(salt_iv), NULL, NULL);

							for (int i = 0; i < pocet_riadkov; i++)
							{

								udaj[i].clear();
								zasifrovany_udaj[i].clear();
								novy_riadok[i] = udaj_meno[i] + (char)0xff + udaj_byty[i];

								CBC_Mode<AES>::Encryption zasifrovanie;
								zasifrovanie.SetKeyWithIV(hlavny_kluc, sizeof(hlavny_kluc), hlavny_kluc_iv);
								StringSource(novy_riadok[i], true, new StreamTransformationFilter(zasifrovanie, new StringSink(udaj[i]), BlockPaddingSchemeDef::PKCS_PADDING));

								zakodovanie.Attach(new StringSink(na_zapis_base64[i]));
								zakodovanie.Put((unsigned char*)udaj[i].data(), udaj[i].size());
								zakodovanie.MessageEnd();
								word64 size = zakodovanie.MaxRetrievable();
								if (size && size <= SIZE_MAX) { na_zapis_base64[i].resize(size); zakodovanie.Get((unsigned char*)&na_zapis_base64[0], na_zapis_base64[i].size()); }
								zakodovanie.Detach(new StringSink(na_zapis_base64[i]));

								string rozdelovac = "\n";
								z = 0;
								pozicia = 0;

								while ((pozicia = na_zapis_base64[i].find(rozdelovac)) != string::npos)
								{
		
									cast[z] = na_zapis_base64[i].substr(0, pozicia);
    								na_zapis_base64[i].erase(0, pozicia + rozdelovac.length());
									z++;

								}

								cast[z] = na_zapis_base64[i].substr(0, pozicia);

								for (int j = 0; j <= z; j++)
								{

									zasifrovany_udaj[i].append(cast[j]);
									cast[j].clear();
	
								}

							}

							FILE *subor_udaje;
							subor_udaje = fopen("data.txt", "w");
							for (int i = 0; i < pocet_riadkov; i++) { if (zasifrovany_udaj[i].length() > 3) { fprintf(subor_udaje, "%s\n", &zasifrovany_udaj[i][0]); } }
							fclose(subor_udaje);

							int msgboxID = MessageBox(NULL, L"Heslo bolo\núspešne zmenené.", L"Zmena hesla", MB_ICONINFORMATION | MB_OK);

							DestroyWindow(hZmenaHesla);
							hZmenaHesla = NULL;

						}
						else
						{
						
							int msgboxID = MessageBox(NULL, L"Heslá nie sú rovnaké.\nProsím vložte rovnaké heslo.", L"Chybné heslo", MB_ICONEXCLAMATION | MB_OK);

						}

					}
					else
					{
				
						int msgboxID = MessageBox(NULL, L"Pôvodné heslo\nnie je zadané správne.", L"Chybné pôvodné heslo", MB_ICONEXCLAMATION | MB_OK);
				
					}

					delete [] buffer_heslo1; buffer_heslo1 = NULL;
					delete [] buffer_heslo2; buffer_heslo2 = NULL;

					return TRUE;
				break;
				}

				case IDCANCEL5:
					DestroyWindow(hZmenaHesla);
					hZmenaHesla = NULL;
					return TRUE;
				break;

				default:
					return TRUE;
				break;

			}
	}

	return FALSE;
}

int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	WNDCLASSEX wcex;
	GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;

	GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_APPLICATION));
    wcex.hCursor        = LoadCursor(NULL, IDC_ARROW);

	if (FILE *file = fopen("background.bmp", "r"))
	{

		fclose(file);
		wcex.hbrBackground = CreatePatternBrush((HBITMAP)LoadImage(0, _T("background.bmp"), IMAGE_BITMAP, 0, 0, LR_CREATEDIBSECTION | LR_LOADFROMFILE));
    
	}
	else
	{
		
		wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
		
	}

	wcex.lpszMenuName   = NULL;
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_APPLICATION));

    if (!RegisterClassEx(&wcex)) { MessageBox(NULL, _T("Call to RegisterClassEx failed!"), _T("Chyba"), NULL); return 1; }

    hInst = hInstance;

	hWnd = CreateWindow(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1200, 600, NULL, NULL, hInstance, NULL);
    if (!hWnd) { MessageBox(NULL, _T("Funkcia CreateWindow zlyhala."), _T("Chyba"), NULL); return 1; }

	ShowWindow(hWnd, nCmdShow);
    	UpdateWindow(hWnd);

	MSG msg;
	HACCEL hAccelTable;

	LoadString(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
	LoadString(hInstance, IDC_ENCRYPTEDMESSAGES01, szWindowClass, MAX_LOADSTRING);
	MyRegisterClass(hInstance);
	
	if (!InitInstance (hInstance, nCmdShow))
	{
		return FALSE;
	}

	hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_ENCRYPTEDMESSAGES01));

	while (GetMessage(&msg, NULL, 0, 0))
	{
		if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	return (int) msg.wParam;
}

ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEX wcex;

	wcex.cbSize = sizeof(WNDCLASSEX);

	wcex.style			= CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc	= WndProc;
	wcex.cbClsExtra		= 0;
	wcex.cbWndExtra		= 0;
	wcex.hInstance		= hInstance;
	wcex.hIcon			= LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ENCRYPTEDMESSAGES01));
	wcex.hCursor		= LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground	= (HBRUSH)(COLOR_WINDOW+1);
	wcex.lpszMenuName	= MAKEINTRESOURCE(IDC_ENCRYPTEDMESSAGES01);
	wcex.lpszClassName	= szWindowClass;
	wcex.hIconSm		= LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

	return RegisterClassEx(&wcex);
}

BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   HWND hWnd;

   hInst = hInstance;

   return TRUE;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;

	switch (message)
	{
	case WM_CREATE:
		{
			hMenubar = CreateMenu();
			hFile = CreateMenu();
			hOptions = CreateMenu();
			
			AppendMenuW(hMenubar, MF_POPUP, (UINT_PTR)hFile, L"&Súbor");
			AppendMenuW(hMenubar, MF_POPUP, (UINT_PTR)hOptions, L"&Pomoc");

			AppendMenuW(hFile, MF_STRING, 201, L"&Nový kontakt");
			AppendMenuW(hFile, MF_STRING, 202, L"&Vymaza zvolený kontakt");
			AppendMenuW(hFile, MF_STRING, 206, L"&Premenova zvolený kontakt");
			AppendMenuW(hFile, MF_STRING, 207, L"&Zmeni hlavné heslo");
			AppendMenuW(hFile, MF_SEPARATOR, NULL, NULL);
			AppendMenuW(hFile, MF_STRING, IDM_EXIT, L"&Ukonèi");

			AppendMenuW(hOptions, MF_STRING, 104, L"&O programe");
			
			SetMenu(hWnd, hMenubar);

			if (FILE *file = fopen("password.txt", "r"))
			{

				fclose(file);
				hHeslo = CreateDialog(hInst, MAKEINTRESOURCE(IDD_DIALOG2), hWnd, (DLGPROC)PasswordProc);
				ShowWindow(hHeslo, SW_SHOW);

			}
			else
			{

				hNoveHeslo = CreateDialog(hInst, MAKEINTRESOURCE(IDD_DIALOG3), hWnd, (DLGPROC)nove_heslo);
				ShowWindow(hNoveHeslo, SW_SHOW);

			}

			hStatic[0] = CreateWindow(L"Static", L"Pôvodný text", WS_BORDER | SS_CENTER | WS_CHILD | WS_VISIBLE | NULL | NULL, 580, 30, 120, 20, hWnd, (HMENU)603, hInst, 0);
			hStatic[1] = CreateWindow(L"Static", L"Zašifrovaný text", WS_BORDER | SS_CENTER | WS_CHILD | WS_VISIBLE | NULL | NULL, 580, 270, 120, 20, hWnd, (HMENU)604, hInst, 0);
			
			hStatic[2] = CreateWindow(L"Static", L"Nie je zvolený kontakt.", WS_BORDER | NULL | WS_CHILD | WS_VISIBLE | NULL | NULL, 250, 0, 400, 20, hWnd, (HMENU)7, hInst, 0);

			edit[0] = CreateWindow(L"Edit", NULL, WS_BORDER | NULL | WS_CHILD | WS_VISIBLE | NULL | WS_VSCROLL | ES_MULTILINE, 250, 60, 800, 200, hWnd, (HMENU)605, hInst, 0);
			edit[1] = CreateWindow(L"Edit", NULL, WS_BORDER | NULL | WS_CHILD | WS_VISIBLE | NULL | WS_VSCROLL | ES_MULTILINE, 250, 300, 800, 200, hWnd, (HMENU)606, hInst, 0);
			
			typ_pisma_pole = CreateFont(16, 0, 0, 0, FW_DONTCARE, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Arial");
            typ_pisma_tlacitko = CreateFont(18, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Times New Roman");
			typ_pisma_nadpis = CreateFont(18, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Times New Roman");
			
			SendMessage(hStatic[0], WM_SETFONT, WPARAM(typ_pisma_nadpis), TRUE);
			SendMessage(hStatic[1], WM_SETFONT, WPARAM(typ_pisma_nadpis), TRUE);
			SendMessage(hStatic[2], WM_SETFONT, WPARAM(typ_pisma_nadpis), TRUE);

			SendMessage(edit[0], WM_SETFONT, WPARAM(typ_pisma_pole), TRUE);
			SendMessage(edit[1], WM_SETFONT, WPARAM(typ_pisma_pole), TRUE);

			hEncrypt = CreateWindow(L"Button", L"Zašifrova", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 1070, 140, 100, 40, hWnd, (HMENU)501, hInst, NULL);
			SendMessage(hEncrypt, WM_SETFONT, WPARAM(typ_pisma_tlacitko), TRUE);
			vykonanie = (WNDPROC)SetWindowLong(hEncrypt, GWL_WNDPROC, (LONG)ButtonProc01);

			hDecrypt = CreateWindow(L"Button", L"Dešifrova", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 1070, 390, 100, 40, hWnd, (HMENU)502, hInst, NULL);
			SendMessage(hDecrypt, WM_SETFONT, WPARAM(typ_pisma_tlacitko), TRUE);
			vykonanie = (WNDPROC)SetWindowLong(hDecrypt, GWL_WNDPROC, (LONG)ButtonProc01);

			break;
		}

	case WM_COMMAND:
		wmId = LOWORD(wParam);
		wmEvent = HIWORD(wParam);

		if (wmId > 1000 && wmId < 1032) { cislo_tlacitka = wmId - 1001; wmId = 1001; }

		switch (wmId)
		{

		case 201:
		{
			if (!IsWindow(hwndGoto)) 
            { 
                hwndGoto = CreateDialog(hInst, MAKEINTRESOURCE(IDD_DIALOG1), hWnd, (DLGPROC)GoToProc);
                ShowWindow(hwndGoto, SW_SHOW);
            } 

			break;
		}

		case 202:
		{
			vymazanie_kontaktu();
			break;
		}

		case 206:
		{
			if (!IsWindow(hNoveMeno)) 
            {
                hNoveMeno = CreateDialog(hInst, MAKEINTRESOURCE(IDD_DIALOG4), hWnd, (DLGPROC)nove_meno);
                ShowWindow(hNoveMeno, SW_SHOW);
            }

			break;
		}

		case 207:
		{
			if (!IsWindow(hZmenaHesla)) 
            {
                hZmenaHesla = CreateDialog(hInst, MAKEINTRESOURCE(IDD_DIALOG5), hWnd, (DLGPROC)zmena_hesla);
                ShowWindow(hZmenaHesla, SW_SHOW);
            }

			break;
		}

		case 501:
		{
			if (pocet_riadkov > 0)
			{

				string aes_cbc_hmac_sifra, aes_cbc_hmac_zasifrovany_text;

				unsigned char aes_cbc_key[32];
				for (int i = 0; i < 32; i++) { aes_cbc_key[i] = udaj_byty[cislo_tlacitka][i]; }

				unsigned char aes_cbc_iv[16];	
				for (int i = 0; i < 16; i++) { aes_cbc_iv[i] = udaj_byty[cislo_tlacitka][i + 32]; }

				CBC_Mode<AES>::Encryption aes_cbc_hmac_zasifrovanie;
				aes_cbc_hmac_zasifrovanie.SetKeyWithIV(aes_cbc_key, sizeof(aes_cbc_key), aes_cbc_iv);

				unsigned char hmac_key[32];
				for (int i = 0; i < 32; i++) { hmac_key[i] = udaj_byty[cislo_tlacitka][i + 48]; }

				HMAC<SHA256> hmac_autentifikacia;
				hmac_autentifikacia.SetKey(hmac_key, sizeof(hmac_key));

				int dlzka = SendMessage(edit[0], WM_GETTEXTLENGTH, 0, 0);
				wchar_t* buffer = new wchar_t[dlzka + 1];
				SendMessage(edit[0], WM_GETTEXT, (WPARAM)dlzka + 1, (LPARAM)buffer);

				wstring medziretazec(buffer);
				wstring_convert<codecvt_utf8<wchar_t>> konvertovanie_na_utf8;
				string vysledny_retazec = konvertovanie_na_utf8.to_bytes(medziretazec);

				StringSource(vysledny_retazec, true, new StreamTransformationFilter(aes_cbc_hmac_zasifrovanie, new HashFilter(hmac_autentifikacia, new StringSink(aes_cbc_hmac_sifra), true)));
				StringSource(aes_cbc_hmac_sifra, true, new HexEncoder(new StringSink(aes_cbc_hmac_zasifrovany_text)));

				int dlzka2 = aes_cbc_hmac_zasifrovany_text.length();
				wchar_t* buffer2 = new wchar_t[dlzka2 + 1];
				for (int i = 0; i <= dlzka2; i++) { buffer2[i] = NULL; }
				for (int k = 0; k < dlzka2; k++) { buffer2[k] = aes_cbc_hmac_zasifrovany_text[k]; }

				SendMessage(edit[1], WM_SETTEXT, (WPARAM)_tcslen(buffer2), (LPARAM)buffer2);

				delete [] buffer; buffer = NULL;
				delete [] buffer2; buffer2 = NULL;

			}

			return TRUE;
			break;
		}

		case 502:
		{
			if (pocet_riadkov > 0)
			{

				string aes_cbc_hmac_sifra, aes_cbc_hmac_odsifrovany_text;
				kontrola = false;

				int dlzka = SendMessage(edit[1], WM_GETTEXTLENGTH, 0, 0);
				wchar_t* buffer = new wchar_t[dlzka + 1];
				SendMessage(edit[1], WM_GETTEXT, (WPARAM)dlzka + 1, (LPARAM)buffer);

				wstring medziretazec(buffer);
				string vysledny_retazec(medziretazec.begin(), medziretazec.end());

				for (int i = 0; i < vysledny_retazec.length(); i++)
				{
				
					if ((vysledny_retazec[i] >= 0x30 && vysledny_retazec[i] <= 0x39) || (vysledny_retazec[i] >= 0x41 && vysledny_retazec[i] <= 0x46)) { kontrola = true; }
					else
					{
					
						kontrola = false;
						int msgboxID = MessageBox(NULL, L"Nevložili ste zakódovaný\nreazec v platnom formáte.", L"Nesprávny formát reazca", MB_ICONSTOP | MB_OK);
						break;
					
					}
				
				}

				if (kontrola == true)
				{

					unsigned char aes_cbc_key[32];
					for (int i = 0; i < 32; i++) { aes_cbc_key[i] = udaj_byty[cislo_tlacitka][i]; }

					unsigned char aes_cbc_iv[16];	
					for (int i = 0; i < 16; i++) { aes_cbc_iv[i] = udaj_byty[cislo_tlacitka][i + 32]; }

					unsigned char hmac_key[32];
					for (int i = 0; i < 32; i++) { hmac_key[i] = udaj_byty[cislo_tlacitka][i + 48]; }

					CBC_Mode<AES>::Decryption aes_cbc_hmac_rozsifrovanie;
					aes_cbc_hmac_rozsifrovanie.SetKeyWithIV(aes_cbc_key, sizeof(aes_cbc_key), aes_cbc_iv);

					HMAC<SHA256> hmac_autentifikacia;
					hmac_autentifikacia.SetKey(hmac_key, sizeof(hmac_key));

					HexDecoder decoder;
					decoder.Put((unsigned char*)vysledny_retazec.data(), vysledny_retazec.size());
					decoder.MessageEnd();
					word64 size = decoder.MaxRetrievable();
					if (size && size <= SIZE_MAX) { aes_cbc_hmac_sifra.resize(size); decoder.Get((unsigned char*)&aes_cbc_hmac_sifra[0], aes_cbc_hmac_sifra.size()); }

					StringSource(aes_cbc_hmac_sifra, true, new HashVerificationFilter(hmac_autentifikacia, new StreamTransformationFilter(aes_cbc_hmac_rozsifrovanie, new StringSink(aes_cbc_hmac_odsifrovany_text)), 0 | 2 | 16));

					wstring_convert<codecvt_utf8<wchar_t>> konvertovanie_z_utf8;
					wstring aes_cbc_hmac_odsifrovany_text_uft8 = konvertovanie_z_utf8.from_bytes(aes_cbc_hmac_odsifrovany_text);

					int dlzka2 = aes_cbc_hmac_odsifrovany_text_uft8.length();
					wchar_t* buffer2 = new wchar_t[dlzka2 + 1];
					for (int i = 0; i <= dlzka2; i++) { buffer2[i] = NULL; }
					for (int k = 0; k < dlzka2; k++) { buffer2[k] = aes_cbc_hmac_odsifrovany_text_uft8[k]; }

					SendMessage(edit[0], WM_SETTEXT, (WPARAM)_tcslen(buffer2), (LPARAM)buffer2);

					delete [] buffer2; buffer2 = NULL;

				}
				else
				{
				
					SendMessage(edit[1], WM_SETTEXT, (WPARAM)0, (LPARAM)0);
				
				}

				delete [] buffer; buffer = NULL;

			}

			return TRUE;
			break;
		}

		case 601:
		{
			hButton[pocet_riadkov] = CreateWindow(L"Button", (LPCWSTR)lParam, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0 + (40 * pocet_riadkov), 160, 40, hWnd, (HMENU)(1001 + pocet_riadkov), hInst, NULL);
			SendMessage(hButton[pocet_riadkov], WM_SETFONT, WPARAM(typ_pisma_tlacitko), TRUE);
			vykonanie = (WNDPROC)SetWindowLong(hButton[pocet_riadkov], GWL_WNDPROC, (LONG)ButtonProc01);
			pocet_riadkov++;
			break;
		}

		case 1001:
		{
			meno_kontaktu = L"Zvolený kontakt: " + udaj_w[cislo_tlacitka];
			SendMessage(hStatic[2], WM_SETTEXT, (WPARAM)_tcslen(meno_kontaktu.c_str()), (LPARAM)meno_kontaktu.c_str());
			break;
		}

		case IDM_ABOUT:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
			break;

		case IDM_EXIT:
			DestroyWindow(hWnd);
			break;

		default:
			return DefWindowProc(hWnd, message, wParam, lParam);

		}

		break;

	case WM_PAINT:
		
		hdc = BeginPaint(hWnd, &ps);

		if (FILE *file = fopen("background.bmp", "r"))
		{

			fclose(file);
			brush = CreatePatternBrush((HBITMAP)LoadImage(0, _T("background.bmp"), IMAGE_BITMAP, 0, 0, LR_CREATEDIBSECTION | LR_LOADFROMFILE));

		}
		else
		{
		
			brush = CreateSolidBrush(RGB(80, 80, 80));
		
		}

		GetClientRect(hWnd, &r);
		FillRect(hdc, &r, brush);

		DeleteObject(brush);

		EndPaint(hWnd, &ps);
		break;

	case WM_DESTROY:
		PostQuitMessage(0);
		break;

	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}

	return 0;
}

INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}
