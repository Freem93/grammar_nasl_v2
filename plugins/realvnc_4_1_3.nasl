#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34461);
  script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2016/05/16 14:22:07 $");

  script_cve_id("CVE-2008-4770");
  script_bugtraq_id(31832,33263);
  script_osvdb_id(50050);
  script_xref(name:"Secunia", value:"32317");

  script_name(english:"RealVNC VNC Viewer < 4.1.3/4.4.3 Arbitrary Command Execution");
  script_summary(english:"Checks version of vncviewer.exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that may allow execution of
arbitrary code.");
 script_set_attribute(attribute:"description", value:
"The version of RealVNC's VNC Viewer installed on the remote Windows
host is affected by multiple issues :

  - An error in the 'CMsgReader::readRect()' function in
    'common/rfb/CMsgReader.cxx' that comes into play when
    processing encoding types, may allow arbitrary code
    execution on the remote system. If an attacker can trick
    a user on the remote host into connecting to a malicious
    server, he can exploit this issue using specially
    crafted
    messages to compromise that host.

  - By tricking a user to connect to a malicious VNC server,
    it may be possible for an attacker to execute arbitrary
    code on a remote system by sending malicious RFB
    protocol
    data to the remote VNC Viewer component. Note VNC
    servers
    are not affected by this issue.");
 script_set_attribute(attribute:"see_also", value:"http://www.realvnc.com/products/upgrade.html");
 script_set_attribute(attribute:"see_also", value:"http://www.realvnc.com/products/free/4.1/release-notes.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.realvnc.com/products/personal/4.4/release-notes.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.realvnc.com/products/enterprise/4.4/release-notes.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to RealVNC VNC Viewer Free Edition 4.1.3 / Personal Edition
4.4.3 / Enterprise Edition 4.4.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20);

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/21");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:realvnc:realvnc");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "KB 'SMB/Registry/Enumerated' not set to TRUE.");


function display_dword (dword, nox)
{
 local_var tmp;

 if (isnull(nox) || (nox == FALSE))
   tmp = "0x";
 else
   tmp = "";

 return string (tmp,
               toupper(
                  hexstr(
                    raw_string(
                               (dword >>> 24) & 0xFF,
                               (dword >>> 16) & 0xFF,
                               (dword >>> 8) & 0xFF,
                               dword & 0xFF
                              )
                        )
                      )
               );
}


# Detect which registry key RealVNC's install used.
#
# nb: don't exit if a key isn't found -- we'll check another location later.
list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(0);
key = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod && prod =~ "^RealVNC")
  {
    key = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(.+)\/DisplayName$", replace:"\1", string:name);
    key = str_replace(find:"/", replace:"\", string:key);
    break;
  }
}


# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}


# Find the install path.
path = NULL;

if (!isnull(key))
{
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"InstallLocation");
    if (!isnull(item))
      path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:item[1]);

    RegCloseKey(handle:key_h);
  }
}
# - Look in alternate locations if we haven't found it yet.
if (isnull(path))
{
  key = "SOFTWARE\Classes\VNC.ConnectionInfo\shell\open\command";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(item))
      path = ereg_replace(pattern:'^"(.+)\\\\vncviewer\\.exe".*$', replace:"\1", string:item[1]);

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Grab the version and description from the executable.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\vncviewer.exe", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

desc = NULL;
ver = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);

  ret = GetFileVersionEx(handle:fh);
  if (!isnull(ret)) children = ret['Children'];
  if (!isnull(children))
  {
    varfileinfo = children['VarFileInfo'];
    if (!isnull(varfileinfo))
    {
      translation =
        (get_word (blob:varfileinfo['Translation'], pos:0) << 16) +
        get_word (blob:varfileinfo['Translation'], pos:2);
      translation = tolower(display_dword(dword:translation, nox:TRUE));
    }
    stringfileinfo = children['StringFileInfo'];
    if (!isnull(stringfileinfo) && !isnull(translation))
    {
      data = stringfileinfo[translation];
      if (!isnull(data)) desc = data['FileDescription'];
      else
      {
        data = stringfileinfo[toupper(translation)];
        if (!isnull(data)) desc = data['FileDescription'];
      }
    }
  }

  CloseFile(handle:fh);
}
NetUseDel();


# Check the version number.
if (!isnull(ver) && !isnull(desc))
{
  if ("Free Edition" >< desc) fixed_version = "4.1.3";
  else if ("Personal Edition" >< desc) fixed_version = "4.4.3";
  else if ("Enterprise Edition" >< desc) fixed_version = "4.4.3";

  fix = split(fixed_version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity)
      {
        version = string(ver[0], ".", ver[1], ".", ver[2]);

        report = string(
          "\n",
          desc," ", version, " is installed under :\n",
          "\n",
          "  ", path, "\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}

