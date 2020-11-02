#pragma warning(disable:4996) 
#include<stdio.h> 
#include<stdlib.h> 
#include<conio.h> 
#include<WinSock.h> 
#include<locale.h> 
#pragma comment (lib,"Ws2_32.lib") 



bool IsEmpty(char *MAC)
{
	for (int i = 0; i < 5; i++)
		if (MAC[i] != 0)
			return false;
	return true;
}
void PrintIp(FILE *out, char *IP)
{
	int i;
	for (i = 0; i < 3; i++)
		fprintf(out, "%d.", (unsigned char)IP[i]);
	fprintf(out, "%d\n", (unsigned char)IP[i]);
}
void PrintMac(FILE* out, char* MAC)
{
	int i;
	for (i = 0; i < 5; i++)
		fprintf(out, "%02X:", (unsigned char)MAC[i]);
	fprintf(out, "%02X\n", (unsigned char)MAC[i]);
}


void main()
{
	setlocale(LC_ALL, "Russian");
	char *data, file_name[30];
	// числе фремов
	int frameNumber = 1;
	// число кадров формата ARP
	int ARP = 0;
	// число кадров формата IPv4
	int IPv4 = 0;
	// число кадров формата DIX
	int DIX = 0;
	// число кадров формата SNAP
	int SNAP = 0;
	// число кадров формата RAW
	int RAW = 0;
	// число кадров формата LLC
	int LLC = 0;
	// Указатель на массив данных из файла
	char* frames;

	int file_size = 0, frame_number = 1;

	FILE* in = fopen("ethers07.bin", "rb");
	FILE* out = fopen("Res.txt", "w");

	fseek(in, 0, SEEK_END);//поместить указатель в конец файла 
	file_size = ftell(in);//получить текущее положение указателя

	fseek(in, 0, SEEK_SET);//поместить указатель в начало файла 
	data = new char[file_size];
	fread(data, file_size, 1, in);//считать данные из файла в массив 
	fclose(in);
	fprintf(out, "Размер файла: %d байт\n", file_size);
	char *p = data;//текущее положение указателя 

	while (p < data + file_size)//пока не конец данных 
	{
		fprintf(out, "\nНомер кадра: %d\n", frame_number);
		fprintf(out, "MAC-адрес получателя: ");
		while (IsEmpty(p))
			p += 6;
		PrintMac(out, p);
		fprintf(out, "MAC-адрес отправителя: ");
		PrintMac(out, p + 6);
		unsigned short LT = ntohs(*(unsigned short*)(p + 12));//осуществляет перевод целого 
																//короткого числа из сетевого порядка байт в порядок байт, принятый на компьютере 
		fprintf(out, "LT: %d\n", LT);
		if (LT == 0x0800) //ipv4 2048 
		{
			fprintf(out, "Тип кадра: IPv4\n");
			fprintf(out, "IP отправителя: ");
			PrintIp(out, p + 26);
			fprintf(out, "IP получателя: ");
			PrintIp(out, p + 30);

			LT = ntohs(*(unsigned short*)(p + 16)) + 14;
			p += LT;
			IPv4++;
			frame_number++;
		}
		else
		{
			if (LT == 0x0806) //arp 2054 
			{
				fprintf(out, "Тип кадра: ARP\n");
				p += 28 + 14;
				ARP++;
				frame_number++;
			}
			else
			{
				if (LT > 0x05DC) //dix 1500 
				{
					fprintf(out, "Кадр Ethernet DIX (или Ethernet II)\n");
					DIX++;
				}
				else
				{
					unsigned short F = ntohs(*(unsigned short*)(p + 14));
					if (F == 0xFFFF)//raw 65535 
					{
						fprintf(out, "Кадр Raw 802.3 (или Frame Novell 802.3)\n");
						RAW++;
					}
					else
						if (F == 0xAAAA) //snap 43690 
						{
							fprintf(out, "Кадр Ethernet SNAP\n");
							SNAP++;
						}
						else //llc 
						{
							fprintf(out, "Кадр 802.3/LLC (Кадр 802.3/802.2 или кадр Novell 802.2)\n");
							LLC++;
						}
				}
				p += LT + 14;
				frame_number++;
			}
		}
	}
	fprintf(out, "\nКоличество кадров: %d\n", frame_number - 1);
	fprintf(out, "IPv4: %d\n", IPv4);
	fprintf(out, "ARP: %d\n", ARP);
	fprintf(out, "DIX: %d\n", DIX);
	fprintf(out, "RAW: %d\n", RAW);
	fprintf(out, "SNAP: %d\n", SNAP);
	fprintf(out, "LLC: %d\n", LLC);
	fclose(out);

}
