#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91545);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/08/09 17:45:02 $");

  script_cve_id(
    "CVE-2016-2815",
    "CVE-2016-2818",
    "CVE-2016-2819",
    "CVE-2016-2821",
    "CVE-2016-2822",
    "CVE-2016-2825",
    "CVE-2016-2828",
    "CVE-2016-2829",
    "CVE-2016-2831",
    "CVE-2016-2832",
    "CVE-2016-2833",
    "CVE-2016-2834"
  );
  script_bugtraq_id(
    91072,
    91074,
    91075
  );
  script_osvdb_id(
    139436,
    139437,
    139438,
    139439,
    139440,
    139441,
    139442,
    139443,
    139444,
    139445,
    139446,
    139447,
    139448,
    139449,
    139450,
    139451,
    139452,
    139453,
    139454,
    139455,
    139456,
    139457,
    139459,
    139461,
    139462,
    139463,
    139464,
    139465,
    139466,
    139467,
    139468,
    139469
  );
  script_xref(name:"MFSA", value:"2016-49");
  script_xref(name:"MFSA", value:"2016-50");
  script_xref(name:"MFSA", value:"2016-51");
  script_xref(name:"MFSA", value:"2016-52");
  script_xref(name:"MFSA", value:"2016-54");
  script_xref(name:"MFSA", value:"2016-56");
  script_xref(name:"MFSA", value:"2016-57");
  script_xref(name:"MFSA", value:"2016-58");
  script_xref(name:"MFSA", value:"2016-59");
  script_xref(name:"MFSA", value:"2016-60");
  script_xref(name:"MFSA", value:"2016-61");

  script_name(english:"Firefox < 47 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Mac OS X host is prior
to 47. It is, therefore, affected by multiple vulnerabilities :

  - Multiple memory corruption issues exist that allow an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-2815, CVE-2016-2818)

  - An overflow condition exists that is triggered when
    handling HTML5 fragments in foreign contexts (e.g.,
    under <svg> nodes). An unauthenticated, remote attacker
    can exploit this to cause a heap-based buffer overflow,
    resulting in the execution of arbitrary code.
    (CVE-2016-2819)

  - A use-after-free error exists that is triggered when
    deleting DOM table elements in 'contenteditable' mode.
    An unauthenticated, remote attacker can exploit this to
    dereference already freed memory, resulting in the
    execution of arbitrary code. (CVE-2016-2821)

  - A spoofing vulnerability exists due to improper handling
    of SELECT elements. An unauthenticated, remote attacker
    can exploit this to spoof the contents of the address
    bar. (CVE-2016-2822)

  - A same-origin bypass vulnerability exists that is
    triggered when handling location.host property values
    set after the creation of invalid 'data:' URIs. An
    unauthenticated, remote attacker can exploit this to
    partially bypass same-origin policy protections.
    (CVE-2016-2825)

  - A use-after-free error exists that is triggered when
    destroying the recycle pool of a texture used during the
    processing of WebGL content. An unauthenticated, remote
    attacker can exploit this to dereference already freed
    memory, resulting in the execution of arbitrary code.
    (CVE-2016-2828)

  - A flaw exists in browser/modules/webrtcUI.jsm that is
    triggered when handling a large number of permission
    requests over a small period of time. An
    unauthenticated, remote attacker can exploit this to
    cause the incorrect icon to be displayed in a given
    permission request, potentially resulting in a user
    approving unintended permission requests.
    (CVE-2016-2829)

  - A flaw exists that is triggered when handling paired
    fullscreen and pointerlock requests in combination with
    closing windows. An unauthenticated, remote attacker can
    exploit this to create an unauthorized pointerlock,
    resulting in a denial of service condition.
    Additionally, an attacker can exploit this to conduct
    spoofing and clickjacking attacks. (CVE-2016-2831)

  - An information disclosure vulnerability exists that is
    triggered when handling CSS pseudo-classes. An
    unauthenticated, remote attacker can exploit this
    disclose a list of installed plugins. (CVE-2016-2832)

  - A Content Security Policy (CSP) bypass exists that is
    triggered when handling specially crafted cross-domain
    Java applets. An unauthenticated, remote attacker can
    exploit this to bypass the CSP and conduct cross-site
    scripting attacks. (CVE-2016-2833)

  - Multiple unspecified flaws exist in the Mozilla Network
    Security Services (NSS) component that allow an attacker
    to have an unspecified impact. (CVE-2016-2834)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-49/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-50/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-51/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-52/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-54/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-56/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-57/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-58/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-59/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-60/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-61/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox version 47 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'47', severity:SECURITY_HOLE);
