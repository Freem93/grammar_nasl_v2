#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(26200);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/12 17:12:50 $");

  script_name(english:"VMware Server Detection (Windows)");
  script_summary(english:"Detects if VMware Server is installed");

 script_set_attribute(attribute:"synopsis", value:"An OS Virtualization application is installed on the remote host.");
 script_set_attribute(attribute:"description", value:
"VMware Server, a free OS virtualization solution that allows to run
multiple operating systems on the same host, is installed on the
remote host.");
 script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/products/server/");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/03");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vmware_server");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


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
  exit(0);
}


hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


path = NULL;

key = "SOFTWARE\VMware, Inc.\VMware Server";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  # If VMware is installed...
  item = RegQueryValue(handle:key_h, item:"InstallPath");
  if (!isnull(item))
  {
    path = item[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


if (!path)
{
 NetUseDel();
 exit(0);
}


share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\vmware.exe", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
 NetUseDel();
 exit(0);
}

fh = CreateFile(file:exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}

if (!isnull(ver))
{
  version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
  set_kb_item(name:"VMware/Server/Version", value:version);

  report = string(
           "VMware Server version ", version, " is installed under :\n",
           "\n",
           "  ", path, "\n"
     );
  security_note(port:port, extra:report);
}
# As of VMware Server 2.0 there is no longer a vmware.exe file
# We can grab the version info from vmnat.exe
else
{
  exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\vmnat.exe", string:path);
  fh = CreateFile(file:exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
  if (!isnull(fh))
  {
    ret = GetFileVersionEx(handle:fh);
    if (!isnull(ret)) children = ret['Children'];

    stringfileinfo = children['StringFileInfo'];
    if (!isnull(stringfileinfo))
    {
      foreach key (keys(stringfileinfo))
      {
        data = stringfileinfo[key];
        if (!isnull(data))
        {
          version = ereg_replace(pattern:'([\\d]+.[\\d]+.[\\d]).*', replace:"\1", string:data['FileVersion']);
          if (!isnull(version))
          {
            set_kb_item(name:"VMware/Server/Version", value:version);

            report = string(
                     "VMware Server version ", version, " is installed under :\n",
                     "\n",
                     "  ", path, "\n"
               );
            security_note(port:port, extra:report);
          }
        }
      }
    }
  }
}

# Clean up
NetUseDel();
