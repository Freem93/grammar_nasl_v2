#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71176);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/12/03 21:00:40 $");

  script_cve_id("CVE-2013-6791");
  script_bugtraq_id(64022);
  script_osvdb_id(100398);

  script_name(english:"Microsoft EMET 3.x >= 3.5 / 4.x < 4.0.4913.26122 ASLR Security Bypass");
  script_summary(english:"Checks Microsoft EMET version.");

  script_set_attribute(attribute:"synopsis", value:
"A tool for mitigating security vulnerabilities is potentially affected
by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"Microsoft's Enhanced Mitigation Experience Toolkit (EMET) is installed
on the remote system and is 3.x newer than or equal to 3.5 or 4.x prior
to 4.0.4913.26122.  It is, therefore, potentially affected by a security
bypass vulnerability. 

The application stores function addresses in a predictable way that
could aid an attacker in bypassing Address Space Layout Randomization
(ASLR) protections.");
  # http://blogs.technet.com/b/srd/archive/2013/06/17/emet-4-0-now-available-for-download.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33f7e614");
  script_set_attribute(attribute:"see_also", value:"http://en.nsfocus.com/2013/advisories_0620/150.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMET 4.0.4913.26122 or later.  A possible temporary
mitigation step is to disable EMET.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:enhanced_mitigation_experience_toolkit");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("microsoft_emet_installed.nasl");
  script_require_keys("SMB/Microsoft/EMET/Path");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

path    = get_kb_item_or_exit("SMB/Microsoft/EMET/Path");
version = get_kb_item_or_exit("SMB/Microsoft/EMET/Version");

# Affected
# 3.5 or greater 3.x
# 4.x < 4.0.4913.26122 (proper release)
if (
  ver_compare(ver:version, fix:'3.5', strict:FALSE) >= 0 &&
  ver_compare(ver:version, fix:'4.0.4913.26122', strict:FALSE) < 0
)
{
  port = kb_smb_transport();
  if (!port) port = 445;

  if(report_verbosity > 0)
  {
    report =
      '\n' +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.0.4913.26122' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "EMET", version, path);

