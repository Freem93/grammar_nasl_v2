#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90309);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/11 19:58:29 $");

  script_cve_id(
    "CVE-2015-1819",
    "CVE-2015-5312",
    "CVE-2015-7499",
    "CVE-2015-7500",
    "CVE-2015-7942",
    "CVE-2015-8035",
    "CVE-2015-8242",
    "CVE-2015-8659",
    "CVE-2016-0801",
    "CVE-2016-0802",
    "CVE-2016-1740",
    "CVE-2016-1748",
    "CVE-2016-1750",
    "CVE-2016-1751",
    "CVE-2016-1752",
    "CVE-2016-1753",
    "CVE-2016-1754",
    "CVE-2016-1755",
    "CVE-2016-1762",
    "CVE-2016-1775",
    "CVE-2016-1783",
    "CVE-2016-1784",
    "CVE-2016-1950"
  );
  script_bugtraq_id(
    75570,
    77390,
    77681,
    79507,
    79509,
    79536,
    79562,
    80438
  );
  script_osvdb_id(
    136124,
    136119,
    136117,
    136114,
    136111,
    136110,
    136107,
    136106,
    136105,
    136104,
    136103,
    136102,
    135603,
    133868,
    133867,
    132239,
    130539,
    130538,
    130536,
    130292,
    129696,
    121175,
    120600
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-03-21-3");

  script_name(english:"Apple TV < 9.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote Apple TV device is a version prior
to 9.2. It is, therefore, affected by the following vulnerabilities :

  - An XML external entity (XXE) expansion flaw exists in
    libxml2 due to the XML parser accepting entities from
    untrusted sources. An unauthenticated, remote attacker
    can exploit this, via crafted XML data, to cause a
    denial of service through resource exhaustion.
    (CVE-2015-1819)

  - An XML external entity (XXE) injection flaw exists in
    libxml2 in file parser.c due to the XML parser accepting
    entities from untrusted sources. An unauthenticated,
    remote attacker can exploit this, via crafted XML data,
    to cause a denial of service or to disclose sensitive
    information. (CVE-2015-5312)

  - A heap buffer overflow condition exists in libxml2 in
    the xmlGROW() function within file parser.c while
    handling XML data. An unauthenticated, remote attacker
    can exploit this to disclose sensitive information.
    (CVE-2015-7499)

  - An out-of-bounds heap read error exists in libxml2 in
    the xmlParseMisc() function within file parser.c while
    handling entity boundaries. An unauthenticated, remote
    attacker can exploit this to cause a denial of service.
    (CVE-2015-7500)

  - An out-of-bounds read error exists in libxml2 in the
    xmlParseConditionalSections() function within file
    parser.c due to a failure to properly skip intermediary
    entities when it stops parsing invalid input. An
    unauthenticated, remote attacker can exploit this, via
    crafted XML data, to cause a denial of service.
    (CVE-2015-7942)

  - An flaw exists in libxml2 in the xz_decomp() function
    within file xzlib.c due to a failure to properly detect
    compression errors when handling compressed XML content.
    An unauthenticated, remote attacker can exploit this,
    via crafted XML data, to cause an infinite loop,
    resulting in a denial of service.
    (CVE-2015-8035)

  - A out-of-bounds read error exists in libxml2 in the
    xmlSAX2TextNode() function within file SAX2.c due to
    improper sanitization of input data. An unauthenticated,
    remote attacker can exploit this, via crafted XML data,
    to cause a denial of service or to disclose sensitive
    information. (CVE-2015-8242)

  - A use-after-free error exists in Nghttp2 within file
    lib/nghttp2_session.c when handling idle streams. An
    unauthenticated, remote attacker can exploit this to
    deference already freed memory, allowing the execution
    of arbitrary code. (CVE-2015-8659)

  - An overflow condition exists in the Broadcom Wi-Fi
    driver due to improper validation of data while handling
    SSID or WPS_ID_DEVICE_NAME values. An unauthenticated,
    adjacent attacker can exploit this, via a crafted
    wireless control message packet, to cause a denial of
    service or to execute arbitrary code. (CVE-2016-0801)

  - An overflow condition exists in the Broadcom Wi-Fi
    driver due to improper validation of user-supplied
    input when handling the packet length of event messages.
    An unauthenticated, adjacent attacker can exploit this,
    via a crafted wireless control message packet, to cause
    a denial of service or to execute arbitrary code.
    (CVE-2016-0802)

  - A flaw exists in FontParser due to improper validation
    of user-supplied input when handling encoded fonts that
    contain invalid characters. An unauthenticated, remote
    attacker can exploit this, via a crafted PDF document,
    to corrupt memory, resulting in a denial of service or
    the execution arbitrary code. (CVE-2016-1740)

  - A flaw exists in IOHIDFamily due to improper validation
    of user-supplied input. An unauthenticated, remote
    attacker can exploit this, via a crafted application,
    to gain access to kernel memory layout information.
    (CVE-2016-1748)

  - A use-after-free error exists in the kernel that allows
    an unauthenticated, remote attacker to execute arbitrary
    code via a crafted application. (CVE-2016-1750)

  - A flaw exists in the kernel due to a failure to properly
    restrict execution permissions. An unauthenticated,
    remote attacker can exploit this, via a crafted
    application, to bypass code-signing protection
    mechanisms. (CVE-2016-1751)

  - An unspecified flaw exists in the kernel that allows a
    local attacker to cause a denial of service via a
    crafted application. (CVE-2016-1752)

  - An integer overflow condition exists in the kernel due
    to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this, via
    a crafted application, to gain elevated privileges.
    (CVE-2016-1753)

  - A memory corruption issue exists in the kernel due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to install a malicious application,
    to cause a denial of service or execute arbitrary code.
    CVE-2016-1754)

  - A use-after-free error exists in the AppleKeyStore user
    client when handling multiple threads, which is
    triggered when one thread closes the user client while
    another attempts to call an external method. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to install a malicious application, to
    execute arbitrary code with elevated privileges.
    (CVE-2016-1755)

  - A flaw exists in libxml2 due to improper validation of
    user-supplied input while handling XML content. An
    unauthenticated, remote attacker can exploit this, via a
    crafted XML document, to cause a denial of service or to
    execute arbitrary code. (CVE-2016-1762)

  - An out-of-bounds write error exists in TrueTypeScaler
    due to improper validation of user-supplied input while
    handling bdat tables in TTF fonts. An unauthenticated,
    remote attacker can exploit this, via a crafted TTF
    font, to cause a denial or service or to execute
    arbitrary code. (CVE-2016-1775)

  - A flaw exists in WebKit due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this, via a crafted website, to cause a
    denial of service or execute arbitrary code.
    (CVE-2016-1783)

  - An unspecified flaw exists in the History implementation
    of WebKit that allows an unauthenticated, remote
    attacker to cause a denial of service via a crafted
    website. (CVE-2016-1784)

  - A heap buffer overflow condition exists in Mozilla
    Network Security Services due to improper validation of
    user-supplied input while parsing ASN.1 structures. An
    unauthenticated, remote attacker can exploit this, via
    crafted ASN.1 data in an X.509 certificate, to cause a
    denial of service or execute arbitrary code.
    (CVE-2016-1950)

Note that only 4th generation models are affected by these
vulnerabilities, and this plugin only checks these models.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT206169");
  # http://prod.lists.apple.com/archives/security-announce/2016/Mar/msg00002.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c691f32");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV version 9.2 or later. Note that this update is
available only for 4th generation models.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:X/RC:R");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("appletv_version.nasl");
  script_require_keys("AppleTV/Version", "AppleTV/URL", "AppleTV/Port");
  script_require_ports("Services/www", 7000);

  exit(0);
}

include("appletv_func.inc");
include("audit.inc");

url = get_kb_item('AppleTV/URL');
if (empty_or_null(url)) exit(0, 'Cannot determine Apple TV URL.');
port = get_kb_item('AppleTV/Port');
if (empty_or_null(port)) exit(0, 'Cannot determine Apple TV port.');

build = get_kb_item('AppleTV/Version');
if (empty_or_null(build)) audit(AUDIT_UNKNOWN_DEVICE_VER, 'Apple TV');

model = get_kb_item('AppleTV/Model');
if (empty_or_null(model)) exit(0, 'Cannot determine Apple TV model.');

# fix
fixed_build = "13Y234";
tvos_ver = "9.2"; # for reporting purposes only
gen = 4; # apple tv generation

appletv_check_version(
  build        : build,
  fix          : fixed_build,
  fix_tvos_ver : tvos_ver,
  model        : model,
  gen          : gen,
  severity     : SECURITY_HOLE,
  port         : port,
  url          : url
);
