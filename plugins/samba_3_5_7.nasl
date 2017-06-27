#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52503);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/14 20:22:11 $");

  script_cve_id("CVE-2011-0719");
  script_bugtraq_id(46597);
  script_osvdb_id(71268);
  script_xref(name:"Secunia", value:"43512");

  script_name(english:"Samba 3.x < 3.3.15 / 3.4.12 / 3.5.7 'FD_SET' Memory Corruption");
  script_summary(english:"Checks version of Samba");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by a memory corruption
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba 3.x running on the
remote host is earlier than 3.3.15 / 3.4.12 / 3.5.7. An error exists
in the range checks on file descriptors in the 'FD_SET' macro that
allows stack corruption. This corruption can cause Samba to crash or
to continually try selecting on an improper descriptor set.

An attacker who is able to get a connection to a file share, either
authenticated or via a guest connection, can leverage this issue to
launch a denial of service attack against the affected smbd service.

Note the possibility of arbitrary code execution exists with this type
of vulnerability but has not been confirmed.

Also note that Nessus has not actually tried to exploit this issue or
otherwise determine if one of the patches has been applied.");
  script_set_attribute(attribute:"solution", value:
"Either apply one of the patches referenced in the project's advisory
or upgrade to 3.3.15 / 3.4.12 / 3.5.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.samba.org/show_bug.cgi?id=7949");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/security/CVE-2011-0719.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.3.15.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.4.12.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.5.7.html");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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
  (ver[0] == 3 && ver[1] == 3 && ver[2] < 15) ||
  (ver[0] == 3 && ver[1] == 4 && ver[2] < 12) ||
  (ver[0] == 3 && ver[1] == 5 && ver[2] < 7)
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version  : ' + version +
             '\n  Fixed version      : 3.3.15 / 3.4.12 / 3.5.7\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, 'Samba version '+version+' is listening on port '+port+' and not affected.');
