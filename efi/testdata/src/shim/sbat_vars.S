// SPDX-License-Identifier: BSD-2-Clause-Patent

#ifndef SBAT_VAR_PREVIOUS
# define SBAT_VAR_PREVIOUS "sbat,1,2022010100\n"
#endif
#ifndef SBAT_VAR_LATEST
# define SBAT_VAR_LATEST "sbat,1,2022010100\n"
#endif

	.section .sbatlevel, "a", %progbits
	.balignl 4, 0
	.4byte  0 /* format version for external parsers */
	.globl  sbat_var_payload_header
	.type   sbat_var_payload_header, %object
	.size   sbat_var_payload_header, .Lsbat_var_payload_header_end - sbat_var_payload_header
sbat_var_payload_header:
	.4byte  .Lsbat_var_previous - sbat_var_payload_header
	.4byte  .Lsbat_var_latest - sbat_var_payload_header
.Lsbat_var_payload_header_end:
	.balign	1, 0
.Lsbat_var_previous:
	.ascii SBAT_VAR_PREVIOUS
	.byte	0
	.balign	1, 0
.Lsbat_var_latest:
	.ascii SBAT_VAR_LATEST
	.byte 0
