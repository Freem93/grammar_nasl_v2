#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86762);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/20 14:12:04 $");

  script_cve_id(
    "CVE-2015-4513",
    "CVE-2015-4514",
    "CVE-2015-4515",
    "CVE-2015-4518",
    "CVE-2015-7181",
    "CVE-2015-7182",
    "CVE-2015-7183",
    "CVE-2015-7187",
    "CVE-2015-7188",
    "CVE-2015-7189",
    "CVE-2015-7192",
    "CVE-2015-7193",
    "CVE-2015-7194",
    "CVE-2015-7195",
    "CVE-2015-7196",
    "CVE-2015-7197",
    "CVE-2015-7198",
    "CVE-2015-7199",
    "CVE-2015-7200"
  );
  script_bugtraq_id(
    77412,
    77415,
    77416
  );
  script_osvdb_id(
    129763,
    129764,
    129765,
    129766,
    129767,
    129768,
    129769,
    129770,
    129771,
    129772,
    129773,
    129774,
    129775,
    129776,
    129777,
    129778,
    129779,
    129780,
    129781,
    129782,
    129783,
    129784,
    129785,
    129786,
    129787,
    129788,
    129789,
    129790,
    129791,
    129792,
    129797,
    129798,
    129799,
    129800,
    129801
  );

  script_name(english:"Firefox < 42 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Mac OS X host is prior
to 42. It is, therefore, affected by the following vulnerabilities :

  - Multiple memory corruption issues exist due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit these issues, via a
    specially crafted web page, to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2015-4513, CVE-2015-4514)

  - An information disclosure vulnerability exists when
    handling type 3 messages as part of the NTLM
    authentication exchange. A remote attacker can exploit
    this, via a specially crafted web page that sends an
    NTLM request, to disclose system hostname and windows
    domain information. (CVE-2015-4515)

  - A security bypass vulnerability exists due to the
    whitelist used by Reader View to disable scripts for
    rendered pages being too permissive. A remote attacker
    can exploit this, via specially crafted web page, to
    bypass Content Security Policy (CSP) protections.
    (CVE-2015-4518)

  - An unspecified use-after-poison flaw exists in the
    sec_asn1d_parse_leaf() function in Mozilla Network
    Security Services (NSS) due to improper restriction of
    access to an unspecified data structure. A remote
    attacker can exploit this, via crafted OCTET STRING
    data, to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2015-7181)
  
  - A heap buffer overflow condition exists in the ASN.1
    decoder in Mozilla Network Security Services (NSS) due
    to improper validation of user-supplied input. A remote
    attacker can exploit this, via crafted OCTET STRING
    data, to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2015-7182)

  - An integer overflow condition exists in the
    PL_ARENA_ALLOCATE macro in the Netscape Portable Runtime
    (NSPR) due to improper validation of user-supplied
    input. A remote attacker can exploit this to corrupt
    memory, resulting in a denial of service condition or
    the execution of arbitrary code. (CVE-2015-7183)

  - A security bypass vulnerability exists due to a failure
    to enforce settings when disabling scripts in the Add-on
    SDK panel. A remote attacker can exploit this, via a
    crafted web page, to bypass security restrictions and
    conduct a cross-site scripting attack. (CVE-2015-7187)

  - A same-origin bypass vulnerability exists due to
    improper handling of trailing whitespaces in the IP
    address hostname. A remote attacker can exploit this, by
    appending whitespace characters to an IP address string,
    to bypass the same-origin policy and conduct a
    cross-site scripting attack. (CVE-2015-7188)

  - A race condition exists in the JPEGEncoder() function
    due to improper validation of user-supplied input when
    handling canvas elements. A remote attacker can exploit
    this to cause a heap-based buffer overflow, resulting in
    a denial of service condition or the execution of
    arbitrary code. (CVE-2015-7189)

  - An arbitrary code execution vulnerability exists in the
    accessibility-tools feature due to improper interaction
    with the implementation of the TABLE element. A remote
    attacker can exploit this to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2015-7192)

  - A cross-origin resource sharing (CORS) request bypass
    vulnerability exists due to improper implementation of
    the CORS cross-origin request algorithm for the POST
    method in situations involving an unspecified
    Content-Type header manipulation. A remote attacker can
    exploit this to perform a simple request instead of a
    'preflight' request. (CVE-2015-7193)

  - A buffer underflow condition exists in libjar due to
    improper validation of user-supplied input when handling
    ZIP archives. A remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2015-7194)

  - An information disclosure vulnerability exists due to
    improper parsing of escaped characters in the hostname
    of location headers. A remote attacker can exploit this
    to gain access to arbitrary site-specific token
    information. (CVE-2015-7195)

  - A memory corruption issue exists in the _releaseobject()
    function in dom/plugins/base/nsNPAPIPlugin.cpp due to
    improper deallocation of JavaScript wrappers. A remote
    attacker can exploit this to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2015-7196)

  - A security bypass vulnerability exists due to improperly
    controlling the ability of a web worker to create a
    WebSocket object in the WebSocketImpl::Init() method.
    A remote attacker can exploit this to bypass intended
    mixed-content restrictions. (CVE-2015-7197)

  - A buffer overflow condition exists in TextureStorage11
    in ANGLE due to improper validation of user-supplied
    input. A remote attacker can exploit this to cause a
    denial of service condition or the execution of
    arbitrary code. (CVE-2015-7198)

  - A flaw exists in the AddWeightedPathSegLists() function
    due to missing return value checks during SVG rendering.
    A remote attacker can exploit this, via a crafted SVG
    document, to corrupt memory, resulting in a denial of
    service condition or the execution of arbitrary code.
    (CVE-2015-7199)

  - A flaw exists in the CryptoKey interface implementation
    due to missing status checks. A remote attacker can
    exploit this to make changes to cryptographic keys and
    execute arbitrary code. (CVE-2015-7200)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-116/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-117/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-118/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-121/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-122/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-123/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-126/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-127/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-128/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-129/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-130/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-131/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-132/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-133/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 42 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

if (get_kb_item(kb_base + '/is_esr')) exit(0, 'The Mozilla Firefox installation is in the ESR branch.');

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'42', severity:SECURITY_HOLE);
