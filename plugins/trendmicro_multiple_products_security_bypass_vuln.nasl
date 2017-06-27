#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34050);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/12/04 16:28:14 $");

  script_cve_id("CVE-2008-2433");
  script_bugtraq_id(30792);
  script_xref(name:"Secunia", value:"31373");
  script_osvdb_id(47752);

  script_name(english:"Trend Micro Multiple Products Token Prediction Security Bypass");
  script_summary(english:"Checks CGIOCommon.dll version");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by a
security bypass vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote host is either running Trend Micro OfficeScan or Worry-Free
Business Security. The installed version is affected by a security
bypass vulnerability because it reportedly implements a weak algorithm
to generate random session tokens typically assigned to a successful
authentication request. An attacker can easily brute-force the
authentication token and gain access to the web console.

In some cases it may be possible to execute arbitrary code on the
remote system." );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/495670" );
   # http://www.trendmicro.com/ftp/documentation/readme/OSCE_8.0_Win_EN_CriticalPatch_B1351_readme.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c33a341a");
   # http://www.trendmicro.com/ftp/documentation/readme/OSCE_8.0_SP1_Win_EN_CriticalPatch_B2402_readme.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84d581da");
   # http://www.trendmicro.com/ftp/documentation/readme/OSCE_8.0_SP1_Patch1_Win_EN_CriticalPatch_B3037_readme.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a1c665c");
   # http://www.trendmicro.com/ftp/documentation/readme/Readme_WFBS5%200_EN_CriticalPatch1404.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?12e41037");
  script_set_attribute(attribute:"solution", value:
"Upgrade to :

 - Trend Micro OfficeScan 8.0 Build 1351/2402 or 3307
   depending on the current OfficeScan patch level.
 - Worry-Free Business Security 5.0 Build 1404." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(287);
  script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/27");
  script_set_attribute(attribute:"patch_publication_date", value: "2008/08/22");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:trend_micro:client_server_messaging_suite");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:trend_micro:officescan");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl","http_version.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports("Services/www", 4343, 8080,139, 445);

  exit(0);
}


include("smb_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# Check if we can find an instance of OfficeScan Server or CSM 

found = 0;
ports = add_port_in_list(list:get_kb_list("Services/www"), port:8080);
ports = add_port_in_list(list:ports, port:4343);

foreach port (ports)
{
  w = http_send_recv3(method:"GET", item:"/officescan/default.htm", port:port);
  if (isnull(w))
  {
    debug_print("the web server on port ", port, " did not answer");
    continue;
  }
  buf = strcat(w[0], w[1], '\r\n', w[2]);
  if ("console/html/cgi/cgiChkMasterPwd.exe" >!< buf)
   {
    # Check if WFBS is installed.        
    w = http_send_recv3(method:"GET", item:"/officescan/default_SMB.htm", port:port);
    if (isnull(w))
    {
      debug_print("the web server on port ", port, " did not answer");
      continue;
    }
    buf = strcat(w[0], w[1], '\r\n', w[2]);
   }

  if ("console/html/cgi/cgiChkMasterPwd.exe" >< buf)
   {
    found = 1;
    break;
  }
}

if (report_paranoia < 2)
  if(!found) exit(0);

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

# Connect to the appropriate share.

name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) exit(0);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}

# Figure out where it is installed.

path = NULL;
SP_version = NULL;

key = "SOFTWARE\TrendMicro\OfficeScan\service\Information";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Local_Path");
  if (!isnull(value)) path = value[1];

  value =  RegQueryValue(handle:key_h, item:"ServicePack_Build");
  if (!isnull(value)) SP_version = value[1];

  RegCloseKey(handle:key_h);
}

# Check if Worry-Free Business Server is installed.

wfbs = NULL;
key = "SOFTWARE\TrendMicro\WFBS";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  wfbs = 1;
  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0);
}
NetUseDel(close:FALSE);


# Grab the file version of CGIOCommon.dll
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll   = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Web\Service\CGIOCommon.dll", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:dll,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

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
  for (i=0; i<4; i++)
    ver[i] = int(ver[i]);

  if ( (wfbs && ver[0] == 15 && ver[1] == 0 && ver[2] == 0 && ver[3] < 1404) || # WFBS 5.0 without patch 1404
       (        ver[0] ==  8 && ver[1] == 0 && ver[2] == 0 && ver[3] < 1351) || # OfficeScan 8.0 patch 2 without patch 1351
       (        ver[0] ==  8 && ver[1] == 0 && ver[2] == 0 && SP_version >= 2302 && ver[3] < 2402) || # OfficeScan 8.0 Service Pack 1 without patch 2402
       (        ver[0] ==  8 && ver[1] == 0 && ver[2] == 0 && SP_version >= 3031 && ver[3] < 3037)    # OfficeScan 8.0 Service Pack 1 Patch 1 without patch 3037
     ) 

     # nb: Worry-Free Business Security file version is bumped to 15.0.x.x instead of 5.0.x.x 
     #	   Therefore we only report Trend Micro OfficeScan version with report_verbosity set.	

     if (report_verbosity && !wfbs)
      {
        report = string(
          "\n",
          "Version ", string(ver[0],".",ver[1]," build ",ver[3]), " of Trend Micro OfficeScan\n", 
	  " is installed under :\n", 
          "\n",
          "  ", path, "\n"
        ); 	
      	security_hole(port:port,extra:report);
      }
      else
      	security_hole(port);
}
