#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(47152);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/12 17:12:49 $");

  script_bugtraq_id(40885);

  script_name(english:"Adobe SVG Viewer Circle Transform Remote Code Execution");
  script_summary(english:"Checks if SVG Viewer is installed");

  script_set_attribute(attribute:"synopsis", value:
"An ActiveX control on the remote host has a code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe SVG Viewer on the remote host has a remote code
execution vulnerability. A remote attacker could exploit this by
tricking a user into requesting a maliciously crafted web page,
resulting in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/svg/eol.html");
  script_set_attribute(attribute:"solution", value:
"Adobe stopped supporting SVG Viewer on January 1, 2009. Remove the
software from the system.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/28");

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
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");


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

paths = make_list();
key = "SOFTWARE\Adobe\Adobe SVG Viewer";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);

    if (strlen(subkey))
    {
      key2 = key + "\" + subkey;
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        item = RegQueryValue(handle:key2_h, item:"path");
        if (!isnull(item)) paths = make_list(paths, item[1]);
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (max_index(paths) == 0)
{
  NetUseDel();
  exit(0, 'Evidence of SVG Viewer was not found in the registry.');
}

installs = make_array();
foreach path (paths)
{
  match = eregmatch(string:path, pattern:'^([A-Za-z]):(.*)$');
  if (!match)
  {
    NetUseDel();
    exit(1, 'Error parsing path "'+path+'".');
  }
  share = match[1] + '$';
  dll = match[2];

  NetUseDel(close:FALSE);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to '"+share+"' share.");
  }

  fh = CreateFile(
    file:dll,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (fh)
  {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);

    # sanity check - make sure we're looking at SVG Viewer 3 or earlier
    if (ver && ver[0] <= 3) installs[join(ver, sep:'.')] = path;
  }
  else
  {
    NetUseDel();
    exit(1, 'Error getting version from "'+path+'".');
  }
}

NetUseDel();

if (max_index(keys(installs)) == 0)
  exit(0, 'SVG Viewer was not detected on the remote host.');

if (report_verbosity > 0)
{
  if (max_index(keys(installs)) > 1) s = 's of SVG Viewer were';
  else s = ' of SVG Viewer was';

  report = '\nThe following vulnerable installation'+s+' detected :\n';

  foreach ver (keys(installs))
  {
    report += '\n  Version : '+ver+
              '\n  Path    : '+installs[ver]+'\n';
  }

  security_hole(port:port, extra:report);
}
else security_hole(port);
