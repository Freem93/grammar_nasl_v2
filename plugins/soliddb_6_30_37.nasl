#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42877);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/03 21:08:35 $");

  script_cve_id("CVE-2009-3840");
  script_bugtraq_id(37053);
  script_osvdb_id(60375);
  script_xref(name:"Secunia", value:"37380");

  script_name(english:"IBM solidDB < 6.30.0.37 Invalid Error Code DoS");
  script_summary(english:"Checks version of solid.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM solidDB database server installed on the remote
host is older than 6.30.0.37 (6.3 Fix Pack 3 / 6.3.37), and hence is
affected by a denial of service vulnerability. By sending a specially
crafted packet with a negative error code other than -1, it may be
possible for an attacker to crash the remote database.");
  script_set_attribute(attribute:"see_also", value:"http://www.coresecurity.com/content/ibm-soliddb-errorcode-dos");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2009/Nov/205");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?rs=0&q1=solidb&uid=swg24024510");
  script_set_attribute(attribute:"solution", value:"Upgrade to IBM solidDB 6.30.0.37 (6.3 Fix Pack 3 / 6.3.37).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:soliddb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl","soliddb_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445, "Services/soliddb");

  exit(0);
}

include("smb_func.inc");
include("audit.inc");
include("smb_hotfixes.inc");

if(report_paranoia < 2)
 if(!get_kb_item("Services/soliddb")) exit(0, "The 'Services/soliddb' KB item is missing.");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1,"The 'SMB/Registry/Enumerated' KB item is missing.");

# Get the install path

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
  exit(1,"Can't connect to IPC$ share.");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1,"Can't connect to remote registry.");
}

path = NULL;

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\solid.exe";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  # If SolidDB is installed...
  item = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(item))
    path = item[1];

  RegCloseKey(handle:key_h);
}

if (isnull(path))
{
  # Figure out where the installer recorded information about it.

  list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
  if (isnull(list)) exit(1,"Could not get Uninstall KB.");

  installstring = NULL;
  foreach name (keys(list))
  {
    prod = list[name];
    if (prod && "solidDB " >< prod)
    {
      installstring = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
      installstring = str_replace(find:"/", replace:"\", string:installstring);
      break;
    }
  }

  if(!isnull(installstring))
  {
    key_h = RegOpenKey(handle:hklm, key:installstring, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      # If SolidDB is installed...
      item = RegQueryValue(handle:key_h, item:"InstallLocation");
      if (!isnull(item))
        path = item[1] + "\bin";

      RegCloseKey(handle:key_h);
    }
  }
}

RegCloseKey(handle:hklm);

if(isnull(path))
{
 NetUseDel();
 exit(1,"Could not get path.");
}

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\solid.exe", string:path);
file  = path + "\solid.exe";

NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
 NetUseDel();
 exit(1, "Can't connect to "+ share + " share.");
}

fh = CreateFile(file:exe,
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

# Check the version number.
if (!isnull(ver))
{
  fixed_version = "6.30.0.37";
  fix = split(fixed_version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity > 0)
      {
        version = ver[0] + "." + ver[1] + "." + ver[2] + "." + ver[3];
        report =
          '\n' +
          "File              : " + file + '\n' +
          "Installed version : " + version + '\n' +
          "Fixed version     : " + fixed_version + '\n';
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
      exit(0);
    }
    else if (ver[i] > fix[i])
      break;

 exit(0, "solid.exe version "+version+" is installed and not vulnerable.");
}
else exit(1, "Can't get file version of 'solid.exe'.");
