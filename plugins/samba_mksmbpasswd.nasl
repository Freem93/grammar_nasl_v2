#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17722);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/05/26 16:30:02 $");

  script_cve_id("CVE-2004-0082");
  script_bugtraq_id(9637);
  script_osvdb_id(3919);
  script_xref(name:"RHSA", value:"2004:064");

  script_name(english:"Samba < 3.0.2 mksmbpasswd.sh Uninitialized Passwords");
  script_summary(english:"Checks the version of Samba");

  script_set_attribute(attribute:"synopsis", value:"The remote host might contain a flawed account management script.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba running on the remote
host is earlier than 3.0.2. Such versions are shipped with an account
creation script (mksmbpasswd.sh) that, when utilized to disable a user
account, may overwrite the user's password with the contents of an
uninitialized buffer. This could lead to a disabled account becoming
re-enabled with an easily guessable password.

Note that Nessus has not actually tried to exploit the issue or
determine if the issue has been fixed by a backported patch.");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.0.2.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Samba 3.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/02/09");
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

if (ver[0] == 3 && ver[1] == 0 && ver[2] < 2)
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
}
else exit(0, "The Samba "+version+" install listening on port "+port+" is not affected.");
