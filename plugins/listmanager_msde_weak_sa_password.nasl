#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20728);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/10/27 15:03:54 $");

  script_cve_id("CVE-2005-4145");
  script_osvdb_id(21559);

  script_name(english:"Lyris ListManager MSDE Weak sa Password");
  script_summary(english:"Checks for weak sa password vulnerability in ListManager with MSDE");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server uses a weak password for one of its
administrative accounts.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running ListManager, a web-based
commercial mailing list management application from Lyris.

The version of ListManager on the remote host was installed using
Microsoft SQL Server Desktop Engine (MSDE) for its database backend
along with a weak password for the 'sa' account - 'lyris' followed by
up to 5 digits. An attacker may be able to discover this password by
means of a brute-force attack and gain administrative access to the
database.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e252a917");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Dec/374" );
  script_set_attribute(attribute:"solution", value:
"Assign a strong 'sa' password to MSDE and update the setting for
'$sql_password' in ListManager's 'lmcfg.txt' file.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Lyris ListManager MSDE Weak sa Password');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access", "SMB/transport");
  script_require_ports(139, 445);
  exit(0);
}

#

include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");

# Unless we're being paranoid, make sure MS SQL is running.
port = get_kb_item("Services/mssql");
if (!port) port = 1433;
if (report_paranoia < 2 && !get_port_state(port)) exit(0);


# Connect to the remote registry.
if (!get_kb_item("SMB/registry_full_access")) exit(0);

name    = kb_smb_name();
if (!name) exit(0);
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();
port    = kb_smb_transport();
if (!port) port = 139;

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Find where the software is installed and which database it uses.
key = "SOFTWARE\Lyris technologies Inc.\ListManager\CurrentVersion";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(value)) path = value[1];

  value = RegQueryValue(handle:key_h, item:"Database");
  if (!isnull(value)) db = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


# If the database type is MSDE...
if (db && db == "msde" && path)
{
  NetUseDel(close:FALSE);

  # Read the password from ListManager's config file.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  cfg =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\lmcfg.txt", string:path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc == 1)
  {
    fh = CreateFile(
      file:cfg,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      contents = ReadFile(handle:fh, length:4096, offset:0);
      CloseFile(handle:fh);

      if (contents) {
        pass = strstr(contents, '$sql_password="');
        if (pass) {
          pass = pass - '$sql_password="';
          pass = pass - strstr(pass, '";');
        }
      }
    }
  }
}
NetUseDel();


# There's a problem if the password follows the known pattern.
if (pass && pass =~ "^lyris[0-9]+$")
{
  if (report_verbosity > 0)
  {
    report = string(
      "The 'sa' account uses the password '", pass, "'.\n"
    );
  }
  else report = NULL;

  security_warning(port:port, extra: report);
}
