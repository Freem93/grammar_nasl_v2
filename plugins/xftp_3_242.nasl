#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47701);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/12 17:12:50 $");

  script_bugtraq_id(40470);
  script_xref(name:"EDB-ID",  value:"12834");
  script_xref(name:"Secunia", value:"39554");

  script_name(english:"Xftp < 3.0 Build 242 LIST Response Buffer Overflow");
  script_summary(english:"Checks for vulnerable version of Xftp");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a buffer
overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Xftp, an FTP client for Windows, installed on the
remote host is older than 3.0 Build 242. Such versions are reportedly
affected by a buffer overflow vulnerability.

By tricking a user into double-clicking on a file name included in the
'LIST' command response from a malicious FTP server, it may be
possible for the attacker to trigger a denial of service condition or
to execute arbitrary code on the affected host .");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?68896026");
  script_set_attribute(attribute:"see_also", value:"http://www.netsarang.com/products/xft_update.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Xftp 3.0 Build 243 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");
include("misc_func.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");

name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();




if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

path = NULL;
version = NULL;

key = "SOFTWARE\NetSarang\Xftp";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);

    # HKLM\SOFTWARE\NetSarang\Xftp\3
    if (strlen(subkey) && subkey =~ "^[0-9.]+$")
    {
      key2 = key + "\" + subkey;
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:"Version");
        if (!isnull(value)) version = value[1];

        value = RegQueryValue(handle:key2_h, item:"Path");
        if (!isnull(value)) path = value[1];

        RegCloseKey(handle:key2_h);
      }
    }
    # break if we find version/path
    if(version && path) break;
  }
  RegCloseKey (handle:key_h);
}

RegCloseKey(handle:hklm);

if (isnull(path))
{
 NetUseDel();
 exit(0, "Xftp is not installed.");
}

if (isnull(version))
{
 NetUseDel();
 exit(1, "It was not possible to determine Xftp version installed on the remote host.");
}

NetUseDel(close:FALSE);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\xftp.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
 NetUseDel();
 exit(1, "Can't connect to '"+share+"' share.");
}

fh = CreateFile(file:exe,
	desired_access:GENERIC_READ,
	file_attributes:FILE_ATTRIBUTE_NORMAL,
	share_mode:FILE_SHARE_READ,
	create_disposition:OPEN_EXISTING);

if (!isnull(fh))
{
  CloseFile(handle:fh);
  NetUseDel();

  # Verify that the file exists, but use version
  # obtained from the registry.

  if (ver_compare(ver:version, fix:'3.0.242') == -1)
  {
    if (report_verbosity > 0)
    {
      ver = split(version,sep:".",keep:FALSE);
      version_ui = ver[0] + "." + ver[1] + " Build "+ int(ver[2]);

      report =
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version_ui +
        '\n  Fixed version     : 3.0 Build 243\n';
         security_hole(port:get_kb_item("SMB/transport"), extra:report);
    }
    else security_hole(port:get_kb_item("SMB/transport"));
      exit(0);
  }
  else exit(0, "Xftp version " + version + " is installed and thus not affected.");
}
else
{
 NetUseDel();
 exit(1, "File '"+(share-'$')+":"+exe+"' does not exist.");
}
