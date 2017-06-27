#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17723);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/05/26 16:30:02 $");

  script_cve_id("CVE-2004-0186");
  script_bugtraq_id(9619);
  script_osvdb_id(3916);

  script_name(english:"Samba smbmnt Local Privilege Escalation");
  script_summary(english:"Checks the version of Samba");

  script_set_attribute(attribute:"synopsis", value:
"The remote service might be affected by a local privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba running on the remote
host is in the 2.x or 3.x branch. Such versions are shipped with a
utility called 'smbmnt'. When smbmnt has the setuid 'root' bit set, a
local user with access to the victim can mount a Samba share and then
execute a setuid or setgid 'root' binary located on the share to gain
unauthorized access to root privileges.

Note that Nessus has not tried to exploit the issue, but rather only
checked the version of Samba running on the remote host. As a result,
it will not detect if the remote host has implemented a workaround.");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=107636290906296&w=2");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.0.6.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade Samba to version 3.0.2a or higher. As a workaround, remove the
setuid bit from 'smbmnt'.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport", "Settings/PCI_DSS");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item_or_exit("SMB/transport");

lanman = get_kb_item_or_exit("SMB/NativeLanManager");
if ("Samba " >!< lanman) exit(0, "The SMB service listening on port "+port+" is not running Samba.");

version = lanman - 'Samba ';
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# 2.x and 3.x are affected (under 3.0.2a)
if (
  ver[0] == 2 ||
  (
    ver[0] == 3 && ver[1] == 0 &&
    (
      ver[2] < 2 ||
      version =~ "^3\.0\.2($|[^a0-9])"
    )
  )
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version  : ' + version +
      '\n  Fixed version      : 3.0.2' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The Samba "+version+" install listening on port "+port+" is not affected.");
