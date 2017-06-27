#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34969);
  script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2015/01/12 17:12:44 $");

  script_cve_id("CVE-2008-5381");
  script_bugtraq_id(32438);
  script_osvdb_id(50064);
  script_xref(name:"Secunia", value:"32846");

  script_name(english:"Ffdshow < rev2347_20081123 Remote Buffer Overflow");
  script_summary(english:"Checks version of ffdshow.ax");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a
remote buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"ffdshow, a DirectShow filter and VFW codec for multiple audio and
video formats, is installed on the remote host.

ffdshow is available as a standalone package but is typically bundled
with third-party codec software such as K-lite Codec Pack, XP Codec
Pack, Vista Codec Package and Codec Pack All-in-one.

The installed version fails to perform sufficient boundary checks
while processing very long URLs. By tricking a user into clicking on a
specially crafted stream, it may be possible to execute arbitrary code
on the remote system subject to the user's privileges.");
 # http://web.archive.org/web/20081222053727/http://security.bkis.vn/?p=277
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce9f055b");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/Nov/0540.html" );
 script_set_attribute(attribute:"solution", value:"Upgrade to ffdshow rev2347_20081123 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/26");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

# Figure out where the installer recorded information about it.

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(0);

installstring = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod && "ffdshow" >< prod)
  {
   installstring = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
   installstring = str_replace(find:"/", replace:"\", string:installstring);
   break;
  }
}

# Get the install path

name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#if (!get_port_state(port)) exit(0);

#soc = open_sock_tcp(port);
#if (!soc) exit(0);

#session_init(socket:soc, hostname:name);
if (!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

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

disp_name = NULL;
path = NULL;

# First look at the CLSID.
key = "SOFTWARE\Classes\CLSID\{007FC171-01AA-4B3A-B2DB-062DEE815A1E}\InprocServer321";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}

if(isnull(path))
{
  # If we don't find it, look at uninstall keys.

  key = installstring;

  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    # If ffdshow is installed...
    item = RegQueryValue(handle:key_h, item:"InstallLocation");
    if (!isnull(item))
    path = item[1];

    item = RegQueryValue(handle:key_h, item:"DisplayName");
    if (!isnull(item))
    disp_name = item[1];

    RegCloseKey(handle:key_h);
  }
}

RegCloseKey(handle:hklm);

if (!path)
{
 NetUseDel();
 exit(0);
}

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);

if("ffdshow.ax" >< path)
ax =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:path);
else
ax =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\ffdshow.ax", string:path);

NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
 NetUseDel();
 exit(0);
}

fh = CreateFile(file:ax,
	desired_access:GENERIC_READ,
	file_attributes:FILE_ATTRIBUTE_NORMAL,
	share_mode:FILE_SHARE_READ,
	create_disposition:OPEN_EXISTING);

ver = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}

NetUseDel();

if (!isnull(ver))
{
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fix = split("1.0.5.2338", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity && ereg(pattern:"^ffdshow \[rev [0-9]+\] \[[0-9]+\-[0-9]+\-[0-9]+\]$",string:disp_name))
      {
        v = eregmatch(pattern:"^ffdshow \[rev ([0-9]+)\] \[([0-9]+)\-([0-9]+)\-([0-9]+)\]$",string:disp_name);
        disp_name = string("ffdshow rev",v[1],"_",v[2],v[3],v[4]);

        report = string(
        "\n",
         disp_name, " is installed on the remote host.\n"
         );
          security_hole(port:port, extra:report);
      }
      else security_hole(port);
        break;
    }
    else if (ver[i] > fix[i])
     break;
}
