#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73689);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/04/30 23:35:28 $");

  script_cve_id("CVE-2014-1646", "CVE-2014-1647");
  script_bugtraq_id(67016, 67020);
  script_osvdb_id(106212, 106213);

  script_name(english:"Symantec Encryption Desktop Multiple DoS Vulnerabilities");
  script_summary(english:"Checks version of Symantec Encryption Desktop");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application installed that is affected by
multiple denial of service vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of Symantec Encryption Desktop
(formerly PGP Desktop) installed that is affected by two denial of
service vulnerabilities due to improper handling of data when parsing
specifically formatted certificates. An attacker could potentially
exploit this vulnerability by tricking a user into attempting to parse
a specially crafted certificate in order to cause an application
crash."
  );
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20140423_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0717a65d");
  script_set_attribute(attribute:"solution", value:"Apply Symantec Encryption Desktop 10.3.2 maintenance pack 1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:encryption_desktop");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pgp:desktop_for_windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

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

max_affected = "10.3.2.15238";
fix = "10.3.2 MP1";
if (
  version =~ "^10\." &&
  ver_compare(ver:version, fix:max_affected, strict:FALSE) <= 0
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
