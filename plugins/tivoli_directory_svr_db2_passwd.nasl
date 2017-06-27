#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47901);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/06/23 19:16:51 $");

  script_bugtraq_id(42015);
  script_osvdb_id(66650);

  script_name(english:"IBM Tivoli Directory Server ldapinst.log DB2 Admin Password Disclosure");
  script_summary(english:"Check for the ldapinst.log file");

  script_set_attribute(attribute:"synopsis", value:
"The remote installation of Tivoli Directory Server stores the login
and password of the DB2 database in a plaintext log file.");
  script_set_attribute(attribute:"description", value:
"The remote installation of Tivoli Directory Server created a file
called 'ldapinst.log' that contains the login and password of the IBM
DB2 database used for this service.

An attacker who could get access to this file (or a backup of it)
would be able to log into the DB2 database and modify its content or
structure.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IO12776");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24027450");
  script_set_attribute(attribute:"solution", value:"Apply the patch from IBM or delete the file.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_directory_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
  script_dependencies("smb_sid2user.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/name", "SMB/login", "SMB/password");
  script_require_ports(139, 445);
  exit(0);
}

#

include("smb_func.inc");
include("audit.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");



admin = get_kb_item("SMB/AdminName");
if ( ! admin ) admin = "Administrator";


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated KB item is missing.");

name = kb_smb_name();
port = kb_smb_transport();
login = kb_smb_login();
pass = kb_smb_password();
domain = kb_smb_domain();


# Connect to the remote registry.

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"C$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

file = strcat("Documents and Settings\", admin, "\ldapinst.log");
fh = CreateFile(
  file               : file,
  desired_access     : GENERIC_READ,
  file_attributes    : FILE_ATTRIBUTE_NORMAL,
  share_mode         : FILE_SHARE_READ,
  create_disposition : OPEN_EXISTING
);
if ( isnull(fh) )
{
  file   = strcat("Users\", admin,"\ldapinst.log");
  fh = CreateFile(
    file               : file,
    desired_access     : GENERIC_READ,
    file_attributes    : FILE_ATTRIBUTE_NORMAL,
    share_mode         : FILE_SHARE_READ,
    create_disposition : OPEN_EXISTING
  );
}

username = "";
password = "";

if (!isnull(fh))
{
  fsize = GetFileSize(handle:fh);
  if (fsize > 65535 ) fsize = 65535;
  for ( i = 0 ; i < 65535 ; i += 4096 )
  {
    data += ReadFile(handle:fh, length:4096, offset:i);
    if (data && 'DB2.USERNAME =' >< data)
    {
      username = strstr(data, 'DB2.USERNAME = ') - 'DB2.USERNAME = ';
      username -= strstr(username, '\r\n');
      if (username) username = chomp(username);
    }
    if (data && 'DB2.PASSWORD =' >< data)
    {
      password = strstr(data, 'DB2.PASSWORD = ') - 'DB2.PASSWORD = ';
      password -= strstr(password, '\r\n');
      if (password) password = chomp(password);
    }
    if ( username && password ) break;
  }
  CloseFile(handle:fh);
}
NetUseDel();

if ( strlen(username) && strlen(password) )
{
  if (report_verbosity > 0)
  {
    report = '\n  File         : ' + file +
             '\n  DB2 username : ' + username +
             '\n  DB2 password : ' + password + '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else exit(0, "The host is not affected.");
