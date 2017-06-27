#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33852);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/11/03 21:08:35 $");

  script_cve_id("CVE-2001-0051");
  script_bugtraq_id(2068);
  script_osvdb_id(9484);

  script_name(english:"Default Password (db2admin) for 'db2admin' Account on Windows");
  script_summary(english:"Attempts to authenticate with default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"An account on the remote Windows host uses a default password.");
  script_set_attribute(attribute:"description", value:
"The 'db2admin' account on the remote Windows host uses a known
password. This account may have been created during installation of
DB2 for use when managing the application, and it likely belongs to
the Local Administrators group.

Note that while the DB2 installation no longer uses a default password
for this account, the upgrade process does not force a password change
if the 'db2admin' account exists from a previous installation.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Dec/97");
  script_set_attribute(attribute:"solution", value:
"Assign a different password to this account as soon as possible.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_login.nasl");
  script_require_keys("SMB/name", "SMB/transport");
  script_exclude_keys("SMB/any_login", "SMB/not_windows", "global_settings/supplied_logins_only");
  script_require_ports(139, 445);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");
if (get_kb_item("SMB/any_login")) exit(0, "The remote host authenticates users as 'Guest'.");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

login = "db2admin";
pass  = "db2admin";


name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
domain  =  kb_smb_domain();
if (empty_or_null(domain)) domain = ".";


# Try using valid credentials.
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
NetUseDel(close:FALSE);
if (rc == -1 && domain != ".")
{
  domain = ".";
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
  NetUseDel();
}
if (rc == 1)
{
  if (report_verbosity > 0)
  {
    report = '\n' + 'Nessus was able to gain access using the following credentials :' +
             '\n' +
             '\n  Login    : ' + login +
             '\n  Password : ' + pass;
    if (domain != ".") report += '\n  Domain   : ' + domain;
    report += '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
