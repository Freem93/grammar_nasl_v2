#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47036);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/19 18:02:18 $");

  script_cve_id("CVE-2010-2063");
  script_bugtraq_id(40884);
  script_osvdb_id(65518);
  script_xref(name:"Secunia", value:"40145");

  script_name(english:"Samba 3.x < 3.3.13 SMB1 Packet Chaining Memory Corruption");
  script_summary(english:"Checks version of Samba");

  script_set_attribute(attribute:"synopsis", value:"The remote service is affected by a memory corruption vulnerability.");

  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba running on the remote
host is a version of 3.x before 3.3.13. Such versions are affected by
a memory corruption vulnerability when handling specially crafted SMB1
packets.

By exploiting this flaw, a remote, unauthenticated attacker could
crash the affected service or potentially execute arbitrary code
subject to the privileges of the user running the affected
application.");

  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/security/CVE-2010-2063.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/security.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Samba 3.3.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba chain_reply Memory Corruption (Linux x86)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("SMB/transport");

lanman = get_kb_item("SMB/NativeLanManager");
if (isnull(lanman)) exit(1, "The 'SMB/NativeLanManager' KB item is missing.");
if ("Samba " >!< lanman) exit(1, "The SMB service listening on port "+port+" is not running Samba.");

version = lanman - 'Samba ';
ver = split(version, sep:'.', keep:FALSE);

for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] == 3 &&
  (
    ver[1] < 3 ||
    (ver[1] == 3 && ver[2] < 13)
  )
)
{
  if (report_verbosity > 1)
  {
    report =
      '\n' +
      'The remote Samba server appears to be :\n' +
      '\n' +
      '  ' + lanman + '\n';
      security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, 'Samba version ' + lanman + ' is listening on port '+port+' and not affected.');
