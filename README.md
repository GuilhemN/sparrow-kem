#	Sparrow-KEM

Copyright (c) 2024 Sparrow KEM Team. See LICENSE.

This repository contains reference code for Sparrow KEM. It is a Split KEM optimized for use in Kwaay, with 
small sizes, and efficient implementation.

#	Root level directory structure of this repository:

*	[ref-c](ref-c): Written in the style of a "portable ANSI C reference implementation" for NIST, and supports NIST API.
*	[scripts](scripts): Python scripts, allowing one to regenerate the constants used in the C code.

We do not include any AVX2, Cortex M4, or FPGA code.

