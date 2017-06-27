#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2012:088. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(59681);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/17 17:13:09 $");

  script_cve_id(
    "CVE-2011-3101",
    "CVE-2012-0441",
    "CVE-2012-1937",
    "CVE-2012-1938",
    "CVE-2012-1939",
    "CVE-2012-1940",
    "CVE-2012-1941",
    "CVE-2012-1944",
    "CVE-2012-1945",
    "CVE-2012-1946",
    "CVE-2012-1947"
  );
  script_bugtraq_id(
    53540,
    53791,
    53792,
    53793,
    53794,
    53796,
    53797,
    53798,
    53799,
    53800,
    53801,
    53808
  );
  script_osvdb_id(
    81963,
    82665,
    82666,
    82667,
    82669,
    82672,
    82673,
    82674,
    82675,
    82676,
    82677
  );
  script_xref(name:"MDVSA", value:"2012:088");
  script_xref(name:"MDVSA", value:"2012:088-1");

  script_name(english:"Mandriva Linux Security Advisory : mozilla (MDVSA-2012:088-1)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security issues were identified and fixed in mozilla firefox and
thunderbird :

Heap-based buffer overflow in the utf16_to_isolatin1 function in
Mozilla Firefox 4.x through 12.0, Firefox ESR 10.x before 10.0.5,
Thunderbird 5.0 through 12.0, Thunderbird ESR 10.x before 10.0.5, and
SeaMonkey before 2.10 allows remote attackers to execute arbitrary
code via vectors that trigger a character-set conversion failure
(CVE-2012-1947)

Use-after-free vulnerability in the nsFrameList::FirstChild function
in Mozilla Firefox 4.x through 12.0, Firefox ESR 10.x before 10.0.5,
Thunderbird 5.0 through 12.0, Thunderbird ESR 10.x before 10.0.5, and
SeaMonkey before 2.10 allows remote attackers to execute arbitrary
code or cause a denial of service (heap memory corruption and
application crash) by changing the size of a container of absolutely
positioned elements in a column (CVE-2012-1940).

Heap-based buffer overflow in the
nsHTMLReflowState::CalculateHypotheticalBox function in Mozilla
Firefox 4.x through 12.0, Firefox ESR 10.x before 10.0.5, Thunderbird
5.0 through 12.0, Thunderbird ESR 10.x before 10.0.5, and SeaMonkey
before 2.10 allows remote attackers to execute arbitrary code by
resizing a window displaying absolutely positioned and relatively
positioned elements in nested columns (CVE-2012-1941).

Use-after-free vulnerability in the nsINode::ReplaceOrInsertBefore
function in Mozilla Firefox 4.x through 12.0, Firefox ESR 10.x before
10.0.5, Thunderbird 5.0 through 12.0, Thunderbird ESR 10.x before
10.0.5, and SeaMonkey before 2.10 might allow remote attackers to
execute arbitrary code via document changes involving replacement or
insertion of a node (CVE-2012-1946).

Mozilla Firefox 4.x through 12.0, Firefox ESR 10.x before 10.0.5,
Thunderbird 5.0 through 12.0, Thunderbird ESR 10.x before 10.0.5, and
SeaMonkey before 2.10 allow local users to obtain sensitive
information via an HTML document that loads a shortcut (aka .lnk) file
for display within an IFRAME element, as demonstrated by a network
share implemented by (1) Microsoft Windows or (2) Samba
(CVE-2012-1945).

The Content Security Policy (CSP) implementation in Mozilla Firefox
4.x through 12.0, Firefox ESR 10.x before 10.0.5, Thunderbird 5.0
through 12.0, Thunderbird ESR 10.x before 10.0.5, and SeaMonkey before
2.10 does not block inline event handlers, which makes it easier for
remote attackers to conduct cross-site scripting (XSS) attacks via a
crafted HTML document (CVE-2012-1944).

Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox before 13.0, Thunderbird before 13.0, and SeaMonkey before
2.10 allow remote attackers to cause a denial of service (memory
corruption and application crash) or possibly execute arbitrary code
via vectors related to (1) methodjit/ImmutableSync.cpp, (2) the
JSObject::makeDenseArraySlow function in js/src/jsarray.cpp, and
unknown other components (CVE-2012-1938).

jsinfer.cpp in Mozilla Firefox ESR 10.x before 10.0.5 and Thunderbird
ESR 10.x before 10.0.5 does not properly determine data types, which
allows remote attackers to cause a denial of service (memory
corruption and application crash) or possibly execute arbitrary code
via crafted JavaScript code (CVE-2012-1939).

Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox 4.x through 12.0, Firefox ESR 10.x before 10.0.5, Thunderbird
5.0 through 12.0, Thunderbird ESR 10.x before 10.0.5, and SeaMonkey
before 2.10 allow remote attackers to cause a denial of service
(memory corruption and application crash) or possibly execute
arbitrary code via unknown vectors (CVE-2012-1937).

Ken Russell of Google reported a bug in NVIDIA graphics drivers that
they needed to work around in the Chromium WebGL implementation.
Mozilla has done the same in Firefox 13 and ESR 10.0.5
(CVE-2011-3101).

The ASN.1 decoder in the QuickDER decoder in Mozilla Network Security
Services (NSS) before 3.13.4, as used in Firefox 4.x through 12.0,
Firefox ESR 10.x before 10.0.5, Thunderbird 5.0 through 12.0,
Thunderbird ESR 10.x before 10.0.5, and SeaMonkey before 2.10, allows
remote attackers to cause a denial of service (application crash) via
a zero-length item, as demonstrated by (1) a zero-length basic
constraint or (2) a zero-length field in an OCSP response
(CVE-2012-0441). NOTE: This flaw was addressed earlier with the
MDVA-2012:036 advisory.

The mozilla firefox and thunderbird packages has been upgraded to the
latest respective versions which is unaffected by these security
flaws.

Additionally the NSPR and the NSS packages has been upgraded to the
latest versions which resolves various upstream bugs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-34.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-36.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-37.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-38.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-39.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-40.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-bn_BD");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-bn_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-en_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-en_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-eo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-es_AR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-es_CL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-es_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-es_MX");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-fy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ga_IE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-gu_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-hy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ku");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-lg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-nb_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-nn_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-oc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-pa_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-pt_PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-sv_SE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ta_LK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:icedtea-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:icedtea-web-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nspr4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nss-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xulrunner10.0.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xulrunner13.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnspr4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnss-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxulrunner10.0.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxulrunner13.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-bn_BD");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-en_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-es_AR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-es_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-fy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-lightning");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-nb_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-nn_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-pt_PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-sv_SE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-ta_LK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nsinstall");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2011");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK2010.1", reference:"firefox-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-af-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-ar-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-be-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-bg-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-bn-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-ca-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-cs-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-cy-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-da-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-de-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-devel-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-el-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-en_GB-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-eo-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-es_AR-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-es_ES-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-et-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-eu-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-fi-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-fr-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-fy-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-ga_IE-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-gl-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-gu_IN-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-he-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-hi-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-hu-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-id-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-is-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-it-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-ja-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-ka-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-kn-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-ko-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-ku-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-lt-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-lv-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-mk-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-mr-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-nb_NO-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-nl-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-nn_NO-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-oc-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-pa_IN-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-pl-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-pt_BR-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-pt_PT-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-ro-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-ru-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-si-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-sk-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-sl-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-sq-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-sr-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-sv_SE-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-te-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-th-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-tr-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-uk-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-zh_CN-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"firefox-zh_TW-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"icedtea-web-1.1.5-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"icedtea-web-javadoc-1.1.5-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64nspr-devel-4.9.1-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64nspr4-4.9.1-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64nss-devel-3.13.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64nss-static-devel-3.13.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64nss3-3.13.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64xulrunner-devel-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64xulrunner10.0.5-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libnspr-devel-4.9.1-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libnspr4-4.9.1-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libnss-devel-3.13.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libnss-static-devel-3.13.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libnss3-3.13.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libxulrunner-devel-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libxulrunner10.0.5-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-ar-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-be-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-bg-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-bn_BD-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-br-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-ca-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-cs-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-da-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-de-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-el-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-en_GB-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-ar-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-ca-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-cs-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-de-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-el-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-es-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-fi-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-fr-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-it-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-ja-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-ko-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-nb-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-nl-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-pl-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-pt-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-pt_BR-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-ru-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-sl-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-sv-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-tr-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-vi-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-zh_CN-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-enigmail-zh_TW-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-es_AR-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-es_ES-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-et-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-eu-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-fi-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-fr-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-fy-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-ga-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-gd-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-gl-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-he-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-hu-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-id-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-is-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-it-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-ja-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-ko-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-lightning-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-lt-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-nb_NO-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-nl-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-nn_NO-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-pl-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-pt_BR-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-pt_PT-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-ro-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-ru-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-si-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-sk-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-sl-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-sq-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-sv_SE-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-ta_LK-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-tr-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-uk-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-vi-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-zh_CN-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mozilla-thunderbird-zh_TW-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"nsinstall-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"nss-3.13.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"xulrunner-10.0.5-0.1mdv2010.2", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2011", reference:"firefox-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-af-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-ar-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-ast-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-be-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-bg-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-bn_BD-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-bn_IN-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-br-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-bs-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-ca-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-cs-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-cy-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-da-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-de-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-devel-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-el-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-en_GB-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-en_ZA-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-eo-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-es_AR-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-es_CL-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-es_ES-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-es_MX-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-et-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-eu-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-fa-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-fi-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-fr-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-fy-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-ga_IE-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-gd-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-gl-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-gu_IN-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-he-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-hi-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-hr-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-hu-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-hy-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-id-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-is-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-it-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-ja-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-kk-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-kn-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-ko-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-ku-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-lg-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-lt-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-lv-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-mai-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-mk-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-ml-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-mr-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-nb_NO-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-nl-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-nn_NO-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-nso-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-or-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-pa_IN-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-pl-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-pt_BR-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-pt_PT-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-ro-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-ru-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-si-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-sk-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-sl-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-sq-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-sr-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-sv_SE-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-ta-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-ta_LK-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-te-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-th-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-tr-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-uk-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-vi-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-zh_CN-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-zh_TW-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"firefox-zu-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"icedtea-web-1.1.5-0.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"icedtea-web-javadoc-1.1.5-0.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64nspr-devel-4.9.1-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64nspr4-4.9.1-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64nss-devel-3.13.5-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64nss-static-devel-3.13.5-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64nss3-3.13.5-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64xulrunner-devel-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64xulrunner13.0-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libnspr-devel-4.9.1-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libnspr4-4.9.1-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libnss-devel-3.13.5-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libnss-static-devel-3.13.5-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libnss3-3.13.5-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libxulrunner-devel-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libxulrunner13.0-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-ar-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-be-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-bg-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-bn_BD-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-br-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-ca-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-cs-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-da-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-de-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-el-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-en_GB-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-enigmail-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-enigmail-ar-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-enigmail-ca-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-enigmail-cs-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-enigmail-de-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-enigmail-el-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-enigmail-es-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-enigmail-fi-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-enigmail-fr-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-enigmail-it-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-enigmail-ja-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-enigmail-ko-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-enigmail-nb-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-enigmail-nl-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-enigmail-pl-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-enigmail-pt-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-enigmail-pt_BR-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-enigmail-ru-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-enigmail-sl-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-enigmail-sv-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-enigmail-tr-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-enigmail-vi-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-enigmail-zh_CN-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-enigmail-zh_TW-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-es_AR-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-es_ES-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-et-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-eu-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-fi-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-fr-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-fy-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-ga-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-gd-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-gl-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-he-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-hu-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-id-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-is-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-it-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-ja-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-ko-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-lightning-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-lt-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-nb_NO-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-nl-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-nn_NO-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-pl-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-pt_BR-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-pt_PT-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-ro-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-ru-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-si-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-sk-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-sl-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-sq-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-sv_SE-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-ta_LK-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-tr-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-uk-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-vi-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-zh_CN-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mozilla-thunderbird-zh_TW-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"nsinstall-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"nss-3.13.5-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"xulrunner-13.0-0.1-mdv2011.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
