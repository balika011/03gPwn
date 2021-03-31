/*
 * Copyright (c) 2021 balika011
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libkirk/kirk_engine.h"
#include "libkirk/AES.h"

struct IPL_BLOCK
{
	uint32_t dest;
	uint32_t size;
	uint32_t jumpTo;
	uint32_t lastSum;
	uint8_t data[0xF30];
};

int main(int argc, char **argv)
{
	if (argc != 3)
	{
		printf("usage: %s <ipl linked to 0xBFC00020> <ipl with exploit>\n", argv[0]);
	}

	kirk_init();

	FILE *f = fopen(argv[1], "rb");
	if (!f)
	{
		printf("Failed to open source!\n");
		return -1;
	}
	
	FILE *o = fopen(argv[2], "wb");
	if (!o)
	{
		printf("Failed to open dest!\n");
		return -1;
	}
	
	struct
	{
		KIRK_CMD1_HEADER cmd1;
		uint8_t padding[0x10];
		struct IPL_BLOCK block;
		uint8_t sha1[0x20];
	} combined;
	
	memset(&combined, 0, sizeof(combined));
	
	combined.block.dest = 0xBC10004C; // SYSREG_RESET_ENABLE_REG
	combined.block.size = 4;
	combined.block.jumpTo = 0x10000005; // b 0xBFC00020
	combined.block.lastSum = 0;
	
	*(uint32_t *) &combined.block.data = 2; // SYSREG_RESET_SC
	
	fread(&combined.block.data[0x10], 1, 0xF00, f); // 0xBFC00020
	
	// Calculate hash
	
	uint32_t *ptr = (uint32_t *)((uint8_t *)&combined.block + combined.block.size);
	ptr[4] = combined.block.dest;
	ptr[5] = combined.block.size;
	combined.block.size += 16;

	uint8_t aes_buffer[sizeof(KIRK_AES128CBC_HEADER) + 0x20];
	
	if (sceUtilsBufferCopyWithRange(&aes_buffer[sizeof(KIRK_AES128CBC_HEADER)], 0x14, (uint8_t *) &combined.block.size, 0x1000, KIRK_CMD_SHA1_HASH))
	{
		printf("Kirk11 failed!\n");
		return -1;
	}
	
	combined.block.size -= 16;

	// Encrypt the hash
	
	KIRK_AES128CBC_HEADER *aes_header = (KIRK_AES128CBC_HEADER *) aes_buffer;
	
	aes_header->mode = KIRK_MODE_ENCRYPT_CBC;
	aes_header->unk_4 = 0;
	aes_header->unk_8 = 0;
	aes_header->keyseed = 0x6C;
	aes_header->data_size = 0x14;
	
	if (sceUtilsBufferCopyWithRange((uint8_t *) aes_header, 0, (uint8_t *) aes_header, 0, KIRK_CMD_ENCRYPT_IV_0))
	{
		printf("Kirk4 failed!\n");
		return -1;
	}
	
	memcpy(combined.sha1, &aes_buffer[sizeof(KIRK_AES128CBC_HEADER)], 0x20);
	
	// Encrypt the block
	
	memset(&combined.cmd1, 0, sizeof(combined.cmd1));
	
	memset(combined.cmd1.AES_key, 0xAA, 16);
	memset(combined.cmd1.CMAC_key, 0xAA, 16);
	combined.cmd1.mode = 1;
	combined.cmd1.data_size = sizeof(combined.block);
	combined.cmd1.data_offset = 0x10;

	AES_ctx k1;
	AES_set_key(&k1, combined.cmd1.AES_key, 128);
	AES_cbc_encrypt(&k1, (uint8_t *) &combined.block, (uint8_t *) &combined.block, combined.cmd1.data_size);
	
	AES_ctx cmac_key;
	AES_set_key(&cmac_key, combined.cmd1.CMAC_key, 128);
	AES_CMAC(&cmac_key, (uint8_t *) &combined.cmd1.mode, 0x30, combined.cmd1.CMAC_header_hash);

	//Make sure data is 16 aligned
	uint32_t chk_size = combined.cmd1.data_size;
	if(chk_size % 16)
		chk_size += 16 - (chk_size % 16);
	AES_CMAC(&cmac_key, (uint8_t *) &combined.cmd1.mode, 0x30 + chk_size + combined.cmd1.data_offset, combined.cmd1.CMAC_data_hash);

	extern AES_ctx aes_kirk1;
	AES_cbc_encrypt(&aes_kirk1, (uint8_t *) &combined.cmd1, (uint8_t *) &combined.cmd1, 32);
	
	// save it
	
	fwrite(&combined, 1, sizeof(combined), o);
	
	fclose(o);
	fclose(f);

	return 0;
}
