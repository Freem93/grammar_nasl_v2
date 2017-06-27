#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77494);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/10/15 20:31:39 $");

  script_cve_id(
    "CVE-2014-1553",
    "CVE-2014-1562",
    "CVE-2014-1563",
    "CVE-2014-1564",
    "CVE-2014-1565",
    "CVE-2014-1567"
  );
  script_bugtraq_id(69519, 69520, 69521, 69523, 69524, 69525);
  #script_osvdb_id();

  script_name(english:"Firefox ESR 31.x < 31.1 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR 31.x installed on the remote Mac OS X host
is prior to 31.1. It is, therefore, affected by the following
vulnerabilities :

  - Multiple memory safety flaws exist within the browser
    engine. Exploiting these, an attacker can cause a denial
    of service or execute arbitrary code. (CVE-2014-1553,
    CVE-2014-1562)

  - A use-after-free vulnerability exists due to improper
    cycle collection when processing animated SVG content.
    A remote attacker can exploit this to cause a denial of
    service or execute arbitrary code. (CVE-2014-1563)

  - Memory is not properly initialized during GIF rendering.
    Using a specially crafted web script, a remote attacker
    can exploit this to acquire sensitive information from
    the process memory. (CVE-2014-1564)

  - The Web Audio API contains a flaw where audio timelines
    are properly created. Using specially crafted API calls,
    a remote attacker can exploit this to acquire sensitive
    information from the process memory or cause a denial of
    service. (CVE-2014-1565)

  - A use-after-free vulnerability exists due to improper
    handling of text layout in directionality resolution.
    A remote attacker can exploit this to execute arbitrary
    code. (CVE-2014-1567)");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/533357/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-67.html");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-68.html");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-69.html");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-70.html");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-72.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox ESR 31.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

is_esr = get_kb_item(kb_base+"/is_esr");
if (isnull(is_esr)) audit(AUDIT_NOT_INST, "Mozilla Firefox ESR");

mozilla_check_version(product:'firefox', version:version, path:path, esr:TRUE, fix:'31.1', min:'31.0', severity:SECURITY_HOLE, xss:FALSE);
