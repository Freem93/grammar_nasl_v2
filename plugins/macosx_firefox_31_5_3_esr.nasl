#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82035);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/04/05 04:38:20 $");

  script_cve_id("CVE-2015-0818");
  script_bugtraq_id(73265);
  script_osvdb_id(119752);

  script_name(english:"Firefox ESR 31.x < 31.5.3 SVG Bypass Privilege Escalation (Mac OS X)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by a
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox ESR 31.x installed on the remote Mac OS
X host is prior to 31.5.3. It is, therefore, affected by a privilege
escalation vulnerability due to a flaw within
'docshell/base/nsDocShell.cpp', which relates to SVG format content
navigation. A remote attacker can exploit this to bypass same-origin
policy protections, allowing a possible execution of arbitrary scripts
in a privileged context.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-28/");

  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox ESR 31.5.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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

mozilla_check_version(product:'firefox', version:version, path:path, esr:TRUE, fix:'31.5.3', min:'31.0', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
