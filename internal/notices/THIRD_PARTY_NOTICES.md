# Third-party notices

owatch carries content from MITRE: MITRE ATT&CK® data inside the binary, references to the Common Weakness Enumeration (CWE™), and identifiers from the Common Attack Pattern Enumeration and Classification (CAPEC™). MITRE's terms of use for each grant a royalty-free license to use it for research, development and commercial purposes, on the condition that any copy reproduces MITRE's copyright designation and the license. It also names the Center for Threat-Informed Defense's mapping of NIST controls to ATT&CK and carries NIST SP 800-53 control titles; their notices follow. It reads FIRST's EPSS scores, CISA's Known Exploited Vulnerabilities catalog, and the FreeBSD project's VuXML, which it does not carry: `owatch data refresh` fetches them into the operator's dataset store, and their terms follow too. This file is that reproduction. It is embedded in the owatch binary, so every copy carries it, and `owatch notices` prints it.

The text inside each fenced block below is the publisher's, reproduced as published.

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

What owatch carries: the identifier, name, abstraction, mapping usage and parent relations of every weakness in the CWE catalog (CWE 5.0), and the description of each weakness a finding maps to, in the binary and in reports, with links to the catalog at cwe.mitre.org. The license below applies to it.

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

## Common Attack Pattern Enumeration and Classification (CAPEC™)

What owatch carries: CAPEC identifiers, for example CAPEC-69, in the basis it states for an ATT&CK technique on a finding, read from CAPEC 3.9. The CAPEC catalog itself is not bundled.

Terms of use, from https://capec.mitre.org/about/termsofuse.html

```text
LICENSE

The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use Common Attack Pattern Enumeration and Classification (CAPEC™) for research, development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce MITRE’s copyright designation and this license in any such copy.

DISCLAIMERS

ALL DOCUMENTS AND THE INFORMATION CONTAINED THEREIN ARE PROVIDED ON AN "AS IS" BASIS AND THE CONTRIBUTOR, THE ORGANIZATION HE/SHE REPRESENTS OR IS SPONSORED BY (IF ANY), THE MITRE CORPORATION, ITS BOARD OF TRUSTEES, OFFICERS, AGENTS, AND EMPLOYEES, DISCLAIM ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTY THAT THE USE OF THE INFORMATION THEREIN WILL NOT INFRINGE ANY RIGHTS OR ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
```

Notice at the foot of the same page:

```text
Use of the Common Attack Pattern Enumeration and Classification (CAPEC), and the associated references from this website are subject to the Terms of Use. Copyright © 2007–2026, The MITRE Corporation. CAPEC and the CAPEC logo are trademarks of The MITRE Corporation.
```

## Center for Threat-Informed Defense, Mappings Explorer

What owatch carries: the basis it states for an ATT&CK technique on a finding names the NIST control that the Center for Threat-Informed Defense's mapping of NIST SP 800-53 Rev 5 to ATT&CK links to the technique (the mapping read was for ATT&CK 16.1, updated 2025-04-16, from https://github.com/center-for-threat-informed-defense/mappings-explorer). The mapping data itself is not bundled. The project's notice and license follow, as published in that repository.

Notice, from the repository's README:

```text
© 2024 MITRE. Approved for public release. Document number(s) CT0104.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under
the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
```

License, from the repository's LICENSE.txt:

```text

                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS
```

## FIRST CVSS v4.0 calculator

What owatch carries: a Go port of the scoring algorithm and the MacroVector lookup table of FIRST's reference CVSS v4.0 calculator (cvss_score.js, cvss_lookup.js, max_composed.js and max_severity.js, from https://github.com/FIRSTdotorg/cvss-v4-calculator, the code FIRST serves at https://www.first.org/cvss/calculator/4.0). It is in `internal/cvss/v4`. The calculator's license, which requires that its copyright notice and conditions be reproduced with binary distributions, follows as published in the repository.

```text
Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## NIST SP 800-53 Rev 5

owatch bundles the control identifiers and titles of NIST Special Publication
800-53 Revision 5, release 5.2.0, read from the OSCAL catalog NIST publishes at
https://github.com/usnistgov/oscal-content. The catalog is a work of the United
States government, in the public domain in the United States, and NIST dedicates
it worldwide under the CC0 1.0 Universal public domain dedication. No condition
attaches to its use; it is credited here because owatch ships it.

## FIRST Exploit Prediction Scoring System (EPSS)

What owatch reads: the daily EPSS scores file FIRST publishes at https://epss.empiricalsecurity.com/epss_scores-current.csv.gz, which `owatch data refresh` fetches into the dataset store. owatch does not carry the scores. FIRST publishes them free of charge and states no license; its EPSS FAQ, https://www.first.org/epss/faq, asks for attribution:

```text
Yes. EPSS scores are published freely via CSV download and API with no registration required. Attribution is requested when EPSS data is used in publications or products.
```

FIRST's EPSS pages credit the scores as follows:

```text
EPSS is maintained by the EPSS Special Interest Group at FIRST. Scores are generated by Empirical Security and published freely to the community.
```

Every report that reads the scores states owatch's own attribution of them: "EPSS scores from FIRST, https://www.first.org/epss, generated by Empirical Security".

## CISA Known Exploited Vulnerabilities Catalog

What owatch reads: the catalog CISA publishes at https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json, which `owatch data refresh` fetches into the dataset store. owatch does not carry the catalog. CISA's license file for it, https://github.com/cisagov/kev-data/blob/develop/LICENSE, opens with the notice below, followed by the CC0 1.0 Universal legal code, which attaches no condition to use.

```text
The KEV database is distributed under the Creative Commons 0 1.0 License. You may use this data in any legal manner but note that information provided at any 3rd party links included in the KEV database are bound by the policies and licenses of those 3rd party websites. Use of the information does not authorize you to use the CISA Logo or DHS Seal, nor should such use be interpreted as an endorsement by CISA or DHS.
```

Every report that reads the catalog states owatch's own attribution of it: "CISA Known Exploited Vulnerabilities Catalog. Use of this information does not authorize use of the CISA Logo or DHS Seal, and is not an endorsement by CISA or DHS."

## VuXML

What owatch reads: the VuXML document of the FreeBSD Ports Collection that vuxml.freebsd.org publishes at https://vuxml.freebsd.org/freebsd/vuln.xml.bz2, the document `pkg audit` reads, which `owatch data refresh` fetches into the dataset store on a FreeBSD host and keeps as it was fetched. owatch does not carry the document; its tests carry an excerpt of it, which keeps the notice below where the document has it, unmodified. The document opens with the license below, and owatch's reports show matches drawn from it, so the license is reproduced here in full.

```text
Copyright 2003-2026 Jacques Vidrine and contributors

Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
HTML, PDF, PostScript, RTF and so forth) with or without modification,
are permitted provided that the following conditions are met:
1. Redistributions of source code (VuXML) must retain the above
   copyright notice, this list of conditions and the following
   disclaimer as the first lines of this file unmodified.
2. Redistributions in compiled form (transformed to other DTDs,
   published online in any format, converted to PDF, PostScript,
   RTF and other formats) must reproduce the above copyright
   notice, this list of conditions and the following disclaimer
   in the documentation and/or other materials provided with the
   distribution.

THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

Every report that reads the document states owatch's own attribution of it: "VuXML, the FreeBSD Ports Collection's vulnerability document, https://vuxml.freebsd.org, copyright Jacques Vidrine and contributors".

## Fedora's updateinfo

What owatch reads: the updateinfo of a Fedora release's updates repository, the file dnf reads, which `owatch data refresh` fetches on a Fedora host. It is found through the repository's index at https://dl.fedoraproject.org/pub/fedora/linux/updates/<release>/Everything/x86_64/repodata/repomd.xml, or for a release Fedora has archived at https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/<release>/Everything/x86_64/repodata/repomd.xml, and checked against the SHA-256 the index states. owatch keeps the release's security updates from it in the dataset store, each update as the file holds it. owatch does not carry the file; its tests carry an excerpt of Fedora 44's updateinfo and that release's index, each with a notice of these terms.

Each update states "Copyright (C) 2026 Red Hat, Inc. and others." and names no license. Fedora's License Approval policy, https://docs.fedoraproject.org/en-US/legal/license-approval/, states that "all software and other content made available by Fedora must be under licenses determined to be allowed in Fedora". The Fedora Project Contributor Agreement, https://docs.fedoraproject.org/en-US/legal/fpca/, defines "Content" to include "non-functional data sets" and licenses content a contributor gives without a license under its default for content, "CC-BY-SA", the Creative Commons Attribution-ShareAlike 4.0 International license, https://creativecommons.org/licenses/by-sa/4.0/legalcode. owatch reads the updateinfo under CC BY-SA 4.0, and the excerpt its tests carry is shared under the same license.

Every report that reads the updateinfo states owatch's own attribution of it: "Fedora's updateinfo, https://fedoraproject.org, copyright Red Hat, Inc. and others".

## Fedora's security tracking bugs

What owatch reads: the open security tracking bugs of a Fedora release, and those filed on rawhide for every release, in Red Hat Bugzilla at https://bugzilla.redhat.com/rest/bug, which `owatch data refresh` asks for anonymously on a Fedora host, in series and with only the fields it needs. owatch keeps facts of each public bug alone, its number, component, status, last change, and the CVEs its summary names, and not its summary or anything naming a person. owatch does not carry the bugs; its tests carry data written for them in Bugzilla's form, and no copy of a real bug.

Red Hat Bugzilla's software is licensed under the Mozilla Public License 2.0 and its documentation under CC BY-SA 4.0; neither license covers the bugs filed in it, and no license states the terms of the bug data. Red Hat Product Security files the tracking bugs, which, as each bug states, are "created by Red Hat Product Security team on a best effort basis", and "Package maintainers are required to ascertain if the flaw indeed affects their package". Fedora Legal has been asked about this use.

Every report that reads the bugs states owatch's own attribution of them: "Fedora's security tracking bugs, Red Hat Bugzilla, https://bugzilla.redhat.com".
