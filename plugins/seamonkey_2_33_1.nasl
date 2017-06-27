#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82042);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/04/05 04:38:20 $");

  script_cve_id("CVE-2015-0817", "CVE-2015-0818");
  script_bugtraq_id(73263, 73265);
  script_osvdb_id(119752, 119794);

  script_name(english:"SeaMonkey < 2.33.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of SeaMonkey.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla SeaMonkey installed on the remote host is prior
to 2.33.1. It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists due to an
    out-of-bounds error in typed array bounds checking
    within 'asmjs/AsmJSValidate.cpp', which relates to
    just-in-time compilation for JavaScript. A remote
    attacker, using a specially crafted web page, can
    exploit this to execute arbitrary code by reading and
    writing to memory. (CVE-2015-0817)

  - A privilege escalation vulnerability exists due to a
    flaw within 'docshell/base/nsDocShell.cpp', which
    relates to SVG format content navigation. A remote
    attacker can exploit this to bypass same-origin policy
    protections, allowing a possible execution of arbitrary
    scripts in a privileged context. (CVE-2015-0818)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-28/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-29/");
  script_set_attribute(attribute:"solution", value:"Upgrade to SeaMonkey 2.33.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");
  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/SeaMonkey/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "SeaMonkey");

mozilla_check_version(installs:installs, product:'seamonkey', fix:'2.33.1', severity:SECURITY_HOLE, xss:FALSE, xsrf:TRUE);
