#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35930);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2009-0712", "CVE-2009-0713");
  script_bugtraq_id(34078);
  script_xref(name:"OSVDB", value:"52591");
  script_xref(name:"OSVDB", value:"52592");
  script_xref(name:"Secunia", value:"34243");

  script_name(english:"HP Systems Insight Manager < 2.5.2.0 WMI Mapper Component Multiple Flaws");
  script_summary(english:"Checks HP Systems Insight Manager version"); 
 
 script_set_attribute(
  attribute:"synopsis", 
  value:
"The remote host has an application that is affected by an unauthorized 
access vulnerability." );
 script_set_attribute(
  attribute:"description", 
  value:
"The remote host is running HP Systems Insight Manager (SIM) for
Windows.  The installed version is older than version 2.5.2.0, and has
a vulnerable version of WMI Mapper component installed.  By exploiting
unspecified vulnerabilities in the WMI Mapper component, it may be
possible for a remote or a local attacker to gain unauthorized access
to data." );

 # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01655638
 script_set_attribute(
  attribute:"see_also", 
  value:"http://www.nessus.org/u?753db126");
 script_set_attribute(
  attribute:"see_also", 
  value:"http://seclists.org/bugtraq/2009/Mar/116" );
 script_set_attribute(
  attribute:"solution", 
  value:"Apply the vendor-supplied patch." );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/03/16");
 script_set_attribute(attribute:"patch_publication_date", value: "2009/03/09");
 script_cvs_date("$Date: 2016/11/19 01:42:50 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:wmi_mapper");
 script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl","http_version.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports("Services/www",139, 445,280,50000,50001,50002);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");
include("http.inc");


# Check if HP Systems Insight is installed.

if (report_paranoia < 2)
{
  ports = add_port_in_list(list:get_kb_list("Services/www"), port:280);
  ports = add_port_in_list(list:ports, port:50000);
  ports = add_port_in_list(list:ports, port:50001);
  ports = add_port_in_list(list:ports, port:50002);
 
  found = 0;

  foreach port (ports)
  {
    if(get_port_state(port))
    { 
      res = http_send_recv3(method:"GET", item:"/", port:port);
      if (!isnull(res) && "Systems Insight Manager" >< res[2])
      {
        found = 1;
        break;
      }
    }
  }
  if(!found) exit(0);
}

# Get the install path

name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if (!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init(socket:soc, hostname:name);
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

key = "SOFTWARE\Hewlett-Packard\Systems Insight Manager\Settings";
path = NULL;
ver  = NULL;

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallPath");
  if (!isnull(item)) path = item[1];

  item = RegQueryValue(handle:key_h, item:"Version");
  if (!isnull(item)) ver = item[1]; 	

  RegCloseKey(handle:key_h);
}

key = "SOFTWARE\The Open Group\WMI Mapper\Settings";
mapper_path = NULL;

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallPath");
  if (!isnull(item)) mapper_path = item[1];

  RegCloseKey(handle:key_h);
}


RegCloseKey(handle:hklm);

if (isnull(path) || isnull(mapper_path))
{
 NetUseDel();
 exit(0);
}

NetUseDel(close:FALSE);

share =  ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe   =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\bin\hprepsim.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
 NetUseDel();
 exit(0);
}

# Check for existence of hprepsim.exe in install directory.

fh = CreateFile(file:exe, 
	desired_access:GENERIC_READ, 
	file_attributes:FILE_ATTRIBUTE_NORMAL, 
	share_mode:FILE_SHARE_READ, 
	create_disposition:OPEN_EXISTING);

if(isnull(fh))
 {
  NetUseDel();
  exit(0);
 }
 
NetUseDel(close:FALSE);

share =  ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:mapper_path);
dll   =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\bin\MapperVersion.dll", string:mapper_path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
 NetUseDel();
 exit(0);
}

# Check for existence of MapperVersion.dll in install directory.

fh = CreateFile(file:dll,
        desired_access:GENERIC_READ,
        file_attributes:FILE_ATTRIBUTE_NORMAL,
        share_mode:FILE_SHARE_READ,
        create_disposition:OPEN_EXISTING);

if (!isnull(fh))
{
  mapper_ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}

if(isnull(fh))
 {
  NetUseDel();
  exit(0);
 }

NetUseDel();

if (ver && mapper_ver)
{
  v = split(ver, sep:".", keep:FALSE);
  for (i=1; i<max_index(v); i++)
    v[i] = int(v[i]);

  # Only HP SIM version prior to 2.5.2 are affected.

  if((v[0] == "C" && v[1]  < 5 ) ||
     (v[0] == "C" && v[1] == 5 && v[2] < 2 )  ||
     (v[0] == "C" && v[1] == 5 && v[2] == 2 && v[3] < 2))
  {

    version = string(v[2],".",v[1],".",v[3]);
	
    fix = split("2.6.4.3", sep:'.', keep:FALSE);
    for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

    for (i=0; i < max_index(mapper_ver); i++)
      if (mapper_ver[i] < fix[i])
      { 
        if (report_verbosity > 0)
        {
          report = string(
            "\n",
            "Version ", version, " HP Systems Insight Manager", "\n",
	    " is installed under :\n",
            "\n",
            "  ", path, "\n"
          );
          security_warning(port:port, extra:report);
        }
        else
          security_warning(port);
         break;
      }
      else if (mapper_ver[i] > fix[i])
      break;
  }
}
