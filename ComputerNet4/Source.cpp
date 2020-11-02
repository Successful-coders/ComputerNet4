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
	// ����� ������
	int frameNumber = 1;
	// ����� ������ ������� ARP
	int ARP = 0;
	// ����� ������ ������� IPv4
	int IPv4 = 0;
	// ����� ������ ������� DIX
	int DIX = 0;
	// ����� ������ ������� SNAP
	int SNAP = 0;
	// ����� ������ ������� RAW
	int RAW = 0;
	// ����� ������ ������� LLC
	int LLC = 0;
	// ��������� �� ������ ������ �� �����
	char* frames;

	int file_size = 0, frame_number = 1;

	FILE* in = fopen("ethers07.bin", "rb");
	FILE* out = fopen("Res.txt", "w");

	fseek(in, 0, SEEK_END);//��������� ��������� � ����� ����� 
	file_size = ftell(in);//�������� ������� ��������� ���������

	fseek(in, 0, SEEK_SET);//��������� ��������� � ������ ����� 
	data = new char[file_size];
	fread(data, file_size, 1, in);//������� ������ �� ����� � ������ 
	fclose(in);
	fprintf(out, "������ �����: %d ����\n", file_size);
	char *p = data;//������� ��������� ��������� 

	while (p < data + file_size)//���� �� ����� ������ 
	{
		fprintf(out, "\n����� �����: %d\n", frame_number);
		fprintf(out, "MAC-����� ����������: ");
		while (IsEmpty(p))
			p += 6;
		PrintMac(out, p);
		fprintf(out, "MAC-����� �����������: ");
		PrintMac(out, p + 6);
		unsigned short LT = ntohs(*(unsigned short*)(p + 12));//������������ ������� ������ 
																//��������� ����� �� �������� ������� ���� � ������� ����, �������� �� ���������� 
		fprintf(out, "LT: %d\n", LT);
		if (LT == 0x0800) //ipv4 2048 
		{
			fprintf(out, "��� �����: IPv4\n");
			fprintf(out, "IP �����������: ");
			PrintIp(out, p + 26);
			fprintf(out, "IP ����������: ");
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
				fprintf(out, "��� �����: ARP\n");
				p += 28 + 14;
				ARP++;
				frame_number++;
			}
			else
			{
				if (LT > 0x05DC) //dix 1500 
				{
					fprintf(out, "���� Ethernet DIX (��� Ethernet II)\n");
					DIX++;
				}
				else
				{
					unsigned short F = ntohs(*(unsigned short*)(p + 14));
					if (F == 0xFFFF)//raw 65535 
					{
						fprintf(out, "���� Raw 802.3 (��� Frame Novell 802.3)\n");
						RAW++;
					}
					else
						if (F == 0xAAAA) //snap 43690 
						{
							fprintf(out, "���� Ethernet SNAP\n");
							SNAP++;
						}
						else //llc 
						{
							fprintf(out, "���� 802.3/LLC (���� 802.3/802.2 ��� ���� Novell 802.2)\n");
							LLC++;
						}
				}
				p += LT + 14;
				frame_number++;
			}
		}
	}
	fprintf(out, "\n���������� ������: %d\n", frame_number - 1);
	fprintf(out, "IPv4: %d\n", IPv4);
	fprintf(out, "ARP: %d\n", ARP);
	fprintf(out, "DIX: %d\n", DIX);
	fprintf(out, "RAW: %d\n", RAW);
	fprintf(out, "SNAP: %d\n", SNAP);
	fprintf(out, "LLC: %d\n", LLC);
	fclose(out);

}
