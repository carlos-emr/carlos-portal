# CARLOS Patient Portal - Notice

## Project Identity

The CARLOS Patient Portal is the patient-facing companion to CARLOS (Clinical Assisting Recording
Ledger Open Source), an independent open-source electronic medical records system. Both are
developed and maintained by the CARLOS community.

## License

Copyright (c) 2026 CARLOS Contributors.

The portal is licensed under the GNU Affero General Public License, version 3 or (at your option)
any later version (`AGPL-3.0-or-later`). The full text is in [`COPYING.md`](COPYING.md). Apart
from that license text and the material listed under "Third-Party Material" below, which keeps its
own license, every file in this repository is under that license.

The portal is new CARLOS Contributors work. It contains no code inherited from OSCAR McMaster or
OpenO EMR, whose copyright notices appear in the CARLOS EMR repository.

CARLOS EMR itself is a separate program under its own license (GPL-2.0-or-later). The portal does
not include or link CARLOS program code; the two communicate only over the portal's network API.

Under section 13 of the AGPL, if you modify the portal and let patients or other users interact
with it over a network, your modified version must prominently offer those users an opportunity to
receive its complete source code (the "Corresponding Source") at no charge.

## Third-Party Material

- **CARLOS Birdman logo** (`carlos_patient_portal/static/carlos-birdman.png`). Taken unchanged
  from CARLOS EMR, where it was added in
  [carlos-emr/carlos#308](https://github.com/carlos-emr/carlos/pull/308). It keeps its CARLOS
  license, the GNU General Public License version 2 or (at your option) any later version
  (`GPL-2.0-or-later`), and is not relicensed by this project. Because that license allows any
  later version, the logo can be used under GPL version 3, whose section 13 permits combining it
  with AGPL-3.0 work such as the portal.
- **Email PDF passphrase wordlist**
  (`carlos_patient_portal/wordlists/patient_pdf_passphrase_english.txt`). Derived in part from
  EFF's Long Wordlist for dice-generated passphrases, published by the Electronic Frontier
  Foundation. The EFF-derived words are used under the license below; the rest of the list is
  under the portal's license.
  Source: https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
  License: Creative Commons Attribution 3.0 United States (CC BY 3.0 US),
  https://creativecommons.org/licenses/by/3.0/us/
  Local changes include filtering for lowercase ASCII words, removing patient-unfriendly terms, and
  reducing the list to 4096 entries.

## Trademark Notice

"OSCAR" is an official mark of McMaster University. Any references to OSCAR in this repository are
for historical and descriptive purposes only and do not imply endorsement by or affiliation with
McMaster University.

## No Affiliation Disclaimer

CARLOS has no organizational affiliation with:
- McMaster University or the Department of Family Medicine
- OpenOSP organization
