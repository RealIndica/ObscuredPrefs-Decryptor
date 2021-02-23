﻿using System;

namespace ObscuredPrefs_Decryptor
{
	// Token: 0x02000493 RID: 1171
	class xxHash
	{
		// Token: 0x06002130 RID: 8496 RVA: 0x000B261C File Offset: 0x000B081C
		public uint CalculateHash(byte[] buf, int len, uint seed = 0U)
		{
			int i = 0;
			uint num7;
			if (len >= 16)
			{
				int num = len - 16;
				uint num2 = seed + 2654435761U + 2246822519U;
				uint num3 = seed + 2246822519U;
				uint num4 = seed;
				uint num5 = seed - 2654435761U;
				do
				{
					uint num6 = (uint)((int)buf[i++] | (int)buf[i++] << 8 | (int)buf[i++] << 16 | (int)buf[i++] << 24);
					num2 += num6 * 2246822519U;
					num2 = (num2 << 13 | num2 >> 19);
					num2 *= 2654435761U;
					num6 = (uint)((int)buf[i++] | (int)buf[i++] << 8 | (int)buf[i++] << 16 | (int)buf[i++] << 24);
					num3 += num6 * 2246822519U;
					num3 = (num3 << 13 | num3 >> 19);
					num3 *= 2654435761U;
					num6 = (uint)((int)buf[i++] | (int)buf[i++] << 8 | (int)buf[i++] << 16 | (int)buf[i++] << 24);
					num4 += num6 * 2246822519U;
					num4 = (num4 << 13 | num4 >> 19);
					num4 *= 2654435761U;
					num6 = (uint)((int)buf[i++] | (int)buf[i++] << 8 | (int)buf[i++] << 16 | (int)buf[i++] << 24);
					num5 += num6 * 2246822519U;
					num5 = (num5 << 13 | num5 >> 19);
					num5 *= 2654435761U;
				}
				while (i <= num);
				num7 = (num2 << 1 | num2 >> 31) + (num3 << 7 | num3 >> 25) + (num4 << 12 | num4 >> 20) + (num5 << 18 | num5 >> 14);
			}
			else
			{
				num7 = seed + 374761393U;
			}
			num7 += (uint)len;
			while (i <= len - 4)
			{
				num7 += (uint)(((int)buf[i++] | (int)buf[i++] << 8 | (int)buf[i++] << 16 | (int)buf[i++] << 24) * -1028477379);
				num7 = (num7 << 17 | num7 >> 15) * 668265263U;
			}
			while (i < len)
			{
				num7 += (uint)buf[i] * 374761393U;
				num7 = (num7 << 11 | num7 >> 21) * 2654435761U;
				i++;
			}
			num7 ^= num7 >> 15;
			num7 *= 2246822519U;
			num7 ^= num7 >> 13;
			num7 *= 3266489917U;
			return num7 ^ num7 >> 16;
		}

		// Token: 0x04001CC1 RID: 7361
		private const uint PRIME32_1 = 2654435761U;

		// Token: 0x04001CC2 RID: 7362
		private const uint PRIME32_2 = 2246822519U;

		// Token: 0x04001CC3 RID: 7363
		private const uint PRIME32_3 = 3266489917U;

		// Token: 0x04001CC4 RID: 7364
		private const uint PRIME32_4 = 668265263U;

		// Token: 0x04001CC5 RID: 7365
		private const uint PRIME32_5 = 374761393U;
	}
}
