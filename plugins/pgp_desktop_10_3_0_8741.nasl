#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64853);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/08/17 02:36:13 $");

  script_cve_id("CVE-2012-4351", "CVE-2012-6533");
  script_bugtraq_id(57835, 57170);
  script_osvdb_id(88920, 89031);

  script_name(english:"Symantec Encryption Desktop Local Access Elevation of Privilege Vulnerabilities");
  script_summary(english:"Checks version of Symantec Encryption Desktop");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application installed that is affected by
multiple privilege escalation vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of Symantec Encryption Desktop (formerly
PGP Desktop) installed that is affected by two privilege escalation
vulnerabilities that can be triggered by exploiting a buffer overflow or
integer overflow flaw in 'pgpwded.sys'. 

By running a specially crafted program, a local attacker could execute
arbitrary code with privileged access."
  );
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2013&suid=20130213_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?511eade5");
  script_set_attribute(attribute:"solution", value:"Apply Symantec Encryption Desktop 10.3.0 maintenance pack 1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:encryption_desktop");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pgp:desktop_for_windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("pgp_desktop_installed.nasl");
  script_require_keys("SMB/symantec_encryption_desktop/Version");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("global_settings.inc");
include("misc_func.inc");

app = 'Symantec Encryption Desktop';
kb_base = "SMB/symantec_encryption_desktop/";
port = kb_smb_transport();

version = get_kb_item_or_exit(kb_base + "Version");
path = get_kb_item_or_exit(kb_base + "Path");

fix = "10.3.0.8741";
if (
  version =~ "^10\." &&
  ver_compare(ver:version, fix:fix, strict:FALSE) == -1
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
