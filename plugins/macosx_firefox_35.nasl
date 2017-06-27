#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80520);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id(
    "CVE-2014-8636",
    "CVE-2014-8642",
    "CVE-2014-8641",
    "CVE-2014-8640",
    "CVE-2014-8639",
    "CVE-2014-8638",
    "CVE-2014-8637",
    "CVE-2014-8634",
    "CVE-2014-8635"
  );
  script_bugtraq_id(
    72041,
    72042,
    72044,
    72045,
    72046,
    72047,
    72048,
    72049,
    72050
  );
  script_osvdb_id(
    117005,
    117009,
    117004,
    117008,
    117007,
    117003,
    117006,
    116998,
    117001,
    116993,
    116994,
    116995,
    116996,
    116997,
    117000,
    117002,
    116999
  );

  script_name(english:"Firefox < 35.0 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Mac OS X host is prior
to 35.0. It is, therefore, affected by the following vulnerabilities :

  - Multiple unspecified memory safety issues exist within
    the browser engine. (CVE-2014-8634, CVE-2014-8635)

  - A flaw exists where DOM objects with some specific
    properties can bypass XrayWrappers. This can allow web
    content to confuse privileged code, potentially
    enabling privilege escalation. (CVE-2014-8636)

  - A flaw exists in the rendering of bitmap images. When
    rending a malformed bitmap image, memory may not always
    be properly initialized, which can result in a leakage
    of data to web content. (CVE-2014-8637)

  - A flaw exists in 'navigator.sendBeacon()' in which it
    does not follow the cross-origin resource sharing
    specification. This results in requests from
    'sendBeacon()' lacking an 'origin' header, which allows
    malicious sites to perform XSRF attacks. (CVE-2014-8638)

  - A flaw exists when receiving 407 Proxy Authentication
    responses with a 'set-cookie' header. This can allow
    a session-fixation attack. (CVE-2014-8639)

  - A flaw exists in Web Audio that cam allow a small block
    of memory to be read. (CVE-2014-8640)

  - A read-after-free flaw exists in WebRTC due to the way
    tracks are handled, which can result in a potentially
    exploitable crash or incorrect WebRTC behavior.
    (CVE-2014-8641)

  - A flaw exists where delegated Online Certificate Status
    Protocol responder certificates fail to recognize the
    id-pkix-ocsp-nocheck extension. This can result in a
    user connecting to a site with a revoked certificate.
    (CVE-2014-8642)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-01/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-02/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-03/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-04/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-05/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-06/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-08/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-09/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 35.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox Proxy Prototype Privileged Javascript Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/14");

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

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'35.0', severity:SECURITY_HOLE, xss:FALSE, xsrf:TRUE);
