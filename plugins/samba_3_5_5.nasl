#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49228);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/13 15:33:29 $");

  script_cve_id("CVE-2010-3069");
  script_bugtraq_id(43212);
  script_osvdb_id(67994);
  script_xref(name:"Secunia", value:"41354");

  script_name(english:"Samba 3.x < 3.5.5 / 3.4.9 / 3.3.14 sid_parse Buffer Overflow");
  script_summary(english:"Checks version of Samba");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba 3.x running on the
remote host is earlier than 3.5.5. The 'sid_parse()' and related
'dom_sid_parse()' functions in such versions fail to correctly check
their input lengths when reading a binary representation of a Windows
SID (Security ID).

An attacker who is able to get a connection to a file share, either
authenticated or via a guest connection, can leverage this issue to
launch a stack-based buffer overflow attack against the affected smbd
service and possibly execute arbitrary code.

Note that Nessus has not actually tried to exploit this issue or
determine if one of the patches has been applied.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.samba.org/show_bug.cgi?id=7669");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/security/CVE-2010-3069.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.5.5.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.4.9.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.3.14.html");
  script_set_attribute(attribute:"solution", value:
"Either apply one of the patches referenced in the project's advisory
or upgrade to 3.5.5 / 3.4.9 / 3.3.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/15");

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
include("misc_func.inc");


if (report_paranoia < 2) audit(AUDIT_PARANOID);


port = get_kb_item("SMB/transport");


lanman = get_kb_item_or_exit("SMB/NativeLanManager");
if ("Samba " >!< lanman) exit(0, "The SMB service listening on port "+port+" is not running Samba.");
if ("Samba 3." >!< lanman) exit(0, "The SMB service listening on port "+port+" is not running Samba 3.x.");

version = lanman - 'Samba ';
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] == 3 && ver[1] < 3) ||
  (ver[0] == 3 && ver[1] == 3 && ver[2] < 14) ||
  (ver[0] == 3 && ver[1] == 4 && ver[2] < 9) ||
  (ver[0] == 3 && ver[1] == 5 && ver[2] < 5)
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version  : ' + version +
             '\n  Fixed version      : 3.5.5 / 3.4.9 / 3.3.14\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, 'Samba version '+version+' is listening on port '+port+' and not affected.');
