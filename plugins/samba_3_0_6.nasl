#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17721);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/05/26 16:30:02 $");

  script_cve_id("CVE-2004-2546");
  script_osvdb_id(23282);

  script_name(english:"Samba < 3.0.6 Unspecified Remote Memory Leak Information Disclosure");
  script_summary(english:"Checks the version of Samba");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a service that contains multiple memory
leaks.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba running on the remote
host is earlier than 3.0.6. Such versions contain multiple memory
leaks that can allow remote, unauthorized information disclosure and a
remote denial of service attack.

Note that Nessus has not actually tried to exploit this issue or
determine if the issue has been fixed by a backported patch.");
  script_set_attribute(attribute:"see_also", value:"http://xforce.iss.net/xforce/xfdb/17139");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.0.6.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Samba 3.0.6 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item_or_exit("SMB/transport");

lanman = get_kb_item_or_exit("SMB/NativeLanManager");
if ("Samba " >!< lanman) exit(0, "The SMB service listening on port "+port+" is not running Samba.");

version = lanman - 'Samba ';
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 3 ||
  (ver[0] == 3 && ver[1] == 0 && ver[2] < 6)
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version  : ' + version +
             '\n  Fixed version      : 3.0.6\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "The Samba "+version+" install listening on port "+port+" is not affected.");
