# Third-party notices

owatch carries content from MITRE: MITRE ATT&CK® data inside the binary, and references to the Common Weakness Enumeration (CWE™). MITRE's terms of use for each grant a royalty-free license to use it for research, development and commercial purposes, on the condition that any copy reproduces MITRE's copyright designation and the license. This file is that reproduction. It is embedded in the owatch binary, so every copy carries it, and `owatch notices` prints it.

The text inside each fenced block below is MITRE's, reproduced as published.

## MITRE ATT&CK®

What owatch carries: for each ATT&CK technique that a finding definition cites, its identifier, name and tactics, and the mitigations the technique's page lists, in `internal/security/registry/data/attack.yaml`. They were read from attack.mitre.org on 2026-11-15, where the current release is ATT&CK v20.1.

Terms of use, from https://attack.mitre.org/resources/legal-and-branding/terms-of-use/

```text
Terms of Use
LICENSE
The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK® for research, development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy.

"© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."

DISCLAIMERS
MITRE does not claim ATT&CK enumerates all possibilities for the types of actions and behaviors documented as part of its adversary model and framework of techniques. Using the information contained within ATT&CK to address or cover full categories of techniques will not guarantee full defensive coverage as there may be undisclosed techniques or variations on existing techniques not documented by ATT&CK.

ALL DOCUMENTS AND THE INFORMATION CONTAINED THEREIN ARE PROVIDED ON AN "AS IS" BASIS AND THE CONTRIBUTOR, THE ORGANIZATION HE/SHE REPRESENTS OR IS SPONSORED BY (IF ANY), THE MITRE CORPORATION, ITS BOARD OF TRUSTEES, OFFICERS, AGENTS, AND EMPLOYEES, DISCLAIM ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTY THAT THE USE OF THE INFORMATION THEREIN WILL NOT INFRINGE ANY RIGHTS OR ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.

See our FAQ for more information on how to use and represent the ATT&CK name.

© 2015 - 2026, The MITRE Corporation. MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation.
```

## Common Weakness Enumeration (CWE™)

What owatch carries: CWE identifiers, and links to the CWE catalog at cwe.mitre.org, in its finding definitions and reports. Where owatch carries other CWE content, the license below applies to it.

Terms of use, from https://cwe.mitre.org/about/termsofuse.html

```text
Terms of Use

CWE™ is free to use by any organization or individual for any research, development, and/or commercial purposes, per these CWE Terms of Use. Accordingly, The MITRE Corporation hereby grants you a non-exclusive, royalty-free license to use CWE for research, development, and commercial purposes. Any copy you make for such purposes is authorized on the condition that you reproduce MITRE’s copyright designation and this license in any such copy. CWE is a trademark of The MITRE Corporation. Please contact cwe@mitre.org if you require further clarification on this issue.

DISCLAIMERS
By accessing information through this site you (as “the user”) hereby agrees the site and the information is provided on an “as is” basis only without warranty of any kind, express or implied, including but not limited to implied warranties of merchantability, availability, accuracy, noninfringement, or fitness for a particular purpose. Use of this site and the information is at the user’s own risk. The user shall comply with all applicable laws, rules, and regulations, and the data source’s restrictions, when using the site.

By contributing information to this site you (as “the contributor”) hereby represents and warrants the contributor has obtained all necessary permissions from copyright holders and other third parties to allow the contributor to contribute, and this site to host and display, the information and any such contribution, hosting, and displaying will not violate any law, rule, or regulation. Additionally, the contributor hereby grants all users of such information a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable license to reproduce, prepare derivative works of, publicly display, publicly perform, sublicense, and distribute such information and all derivative works.

The MITRE Corporation expressly disclaims any liability for any damages arising from the contributor’s contribution of such information, the user’s use of the site or such information, and The MITRE Corporation’s hosting the tool and displaying the information. The foregoing disclaimer specifically includes but is not limited to general, consequential, indirect, incidental, exemplary, or special or punitive damages (including but not limited to loss of income, program interruption, loss of information, or other pecuniary loss) arising out of use of this information, no matter the cause of action, even if The MITRE Corporation has been advised of the possibility of such damages.
```

Notice at the foot of the same page:

```text
Use of the Common Weakness Enumeration (CWE™) and the associated references from this website are subject to the Terms of Use. CWE is sponsored by the U.S. Department of Homeland Security (DHS) Cybersecurity and Infrastructure Security Agency (CISA) and managed by the Homeland Security Systems Engineering and Development Institute (HSSEDI) which is operated by The MITRE Corporation (MITRE). Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation
```

## NIST SP 800-53 Rev 5

owatch bundles the control identifiers and titles of NIST Special Publication
800-53 Revision 5, release 5.2.0, read from the OSCAL catalog NIST publishes at
https://github.com/usnistgov/oscal-content. The catalog is a work of the United
States government, in the public domain in the United States, and NIST dedicates
it worldwide under the CC0 1.0 Universal public domain dedication. No condition
attaches to its use; it is credited here because owatch ships it.
