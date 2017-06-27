#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(33106);
  script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2015/01/29 00:33:21 $");

  script_cve_id("CVE-2008-2100");
  script_bugtraq_id(29552);
  script_osvdb_id(46203);
  script_xref(name:"VMSA", value:"2008-0009");

  script_name(english:"VMware VIX API Multiple Buffer Overflow Vulnerabilities");
  script_summary(english:"Checks if vulnerable version of VIX API is installed");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
buffer overflow vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"VMware VIX, an application programming interface to manipulate virtual
machines is installed on the remote host.

The installed version of VMware VIX API is affected by multiple buffer
overflow vulnerabilities. Successful exploitation of these issues
could allow arbitrary code execution on the host operating system from
the guest system.");
 script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2008-0009.html");
 script_set_attribute(attribute:"solution", value:"Upgrade to VMware VIX API 1.1.4 or higher.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/09");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:ace");
script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:esx_server");
script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:player");
script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:server");
script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:vmware_workstation");
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

# Figure out where the installer recorded information about it.

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(0);

installstring = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod &&  "VMware VIX" >< prod)
  {
   installstring = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
   installstring = str_replace(find:"/", replace:"\", string:installstring);
   installstring1 = ereg_replace(pattern:"^(SMB\/Registry\/HKLM\/SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
   break;
  }
}

if(isnull(installstring) || isnull(installstring1)) exit(0);


vix_version = get_kb_item(string(installstring1,"/","DisplayVersion"));

if (isnull(vix_version)) exit(0);


# Get the install path

name    =  kb_smb_name();
port      =  kb_smb_transport();
login     =  kb_smb_login();
pass     =  kb_smb_password();
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

key = installstring;
path = NULL;


key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  # If VMware VIX is installed...
  item = RegQueryValue(handle:key_h, item:"InstallLocation");
  if (!isnull(item))
  {
    path = item[1];
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


if (!path)
{
 NetUseDel();
 exit(0);
}

# Check if one of the VIX dll is present.

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)[\\]*$", replace:"\1\VixCOM.dll", string:path);

NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
 NetUseDel();
 exit(0);
}

fh = CreateFile(file:dll,
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


if(!isnull(ver))
{
 # Ok, so we could get version for one of the VIX dll's. Now
 # set the kb for vix version we obtained from the registry.

 set_kb_item(name:"VMware/VIX/Version", value:vix_version);
 v = split(vix_version, sep:".", keep:FALSE);

 if (( int(v[0]) < 1 ) ||
     ( int(v[0]) == 1 && int(v[1])  < 1 ) ||
     ( int(v[0]) == 1 && int(v[1]) == 1 && int(v[2]) < 4)
     )
     {
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Version ",vix_version," of VMware VIX API is installed on the remote host.",
          "\n"
        );
        security_hole(port:port, extra:report);
       }
       else
   	 security_hole(port);
     }
}
