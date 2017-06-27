#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24246);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/16 14:22:05 $");

  script_cve_id("CVE-2007-0603");
  script_bugtraq_id(22247);
  script_osvdb_id(32969, 32970);

  script_name(english:"PGP Desktop PGPserv Crafted Data Object Arbitrary Code Execution");
  script_summary(english:"Checks version of PGP Desktop");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a
privilege escalation issue.");
  script_set_attribute(attribute:"description", value:
"The version of PGP Desktop installed on the remote host reportedly can
allow a remote, authenticated user to execute arbitrary code on the
affected host with LOCAL SYSTEM privileges.  The issue arises because
the software operates a service named 'PGPServ' or 'PGPsdkServ' that
exposes a named pipe that fails to validate the object data passed to
it.");
  # http://www.nccgroup.com/en/our-services/security-testing-audit-compliance/information-security-software/#.USPpevKnfkI
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eaff6760");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/458137/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PGP Desktop version 9.5.2 or later, as the change log
suggests the issue has been addressed in that version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:pgp:desktop_for_windows");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:encryption_desktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("pgp_desktop_installed.nasl");
  script_require_keys("SMB/symantec_encryption_desktop/Version");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("global_settings.inc");
include("misc_func.inc");

app = 'PGP Desktop';
kb_base = "SMB/symantec_encryption_desktop/";
port = kb_smb_transport();

version = get_kb_item_or_exit(kb_base + "Version");
path = get_kb_item_or_exit(kb_base + "Path");

fix = "9.5.2.0";
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
