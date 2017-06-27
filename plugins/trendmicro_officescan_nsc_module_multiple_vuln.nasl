#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35451);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/23 20:42:25 $");

  script_cve_id("CVE-2008-3864", "CVE-2008-3865", "CVE-2008-3866");
  script_bugtraq_id(33358);
  script_osvdb_id(53191, 53192, 53193);
  script_xref(name:"Secunia", value:"33609");

  script_name(english:"Trend Micro OfficeScan Client Firewall Multiple Vulnerabilities");
  script_summary(english:"Checks for vulnerable versions of Trend Micro products");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is either running Trend Micro OfficeScan or Trend
Micro OfficeScan Client. The installed version is affected by multiple
vulnerabilities :

  - A vulnerability in 'ApiThread()' function could allow a
    malicious local user to execute arbitrary code with
    SYSTEM privileges by sending specially crafted packets
    to the OfficeScan NT Firewall service (TmPfw.exe)
    listening on TCP port 40000 by default.

  - A vulnerability in 'ApiThread()' function could allow a
    malicious local user to crash the OfficeScan NT Firewall
    service (TmPfw.exe) by sending specially crafted packets
    to its default TCP port 40000.

  - By sending specially crafted packets to the OfficeScan
    NT Firewall service (TmPfw.exe) on its default TCP port
    40000 it may be possible for a local user to modify
    firewall configuration without any authentication.");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2008-42");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2008-43" );
   # http://www.trendmicro.com/ftp/documentation/readme/OSCE8.0_SP1_Patch1_CriticalPatch_3191_Readme.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aac27224" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Trend Micro OfficeScan 8.0 SP1 Patch 1 and apply patch
3191.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 119, 287);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trend_micro:officescan");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");
include("misc_func.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

# Connect to the appropriate share.

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

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}

# Figure out the Software version

# 1.First check if its OfficeScan server.

path = NULL;
server_version = NULL;
SP_version = NULL;

key = "SOFTWARE\TrendMicro\OfficeScan\service\Information";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  # TrendMicro OfficeScan Server install...

  value =  RegQueryValue(handle:key_h, item:"Local_Path");
  if (!isnull(value)) path = value[1];

  value =  RegQueryValue(handle:key_h, item:"Server_Version");
  if (!isnull(value)) server_version = value[1];

  RegCloseKey(handle:key_h);
}

# 2. If path is null, then either OfficeScan server is
#    not installed or its a OfficeScan Client install.

if (isnull(path))
{
  key = "SOFTWARE\TrendMicro\PC-cillinNTCorp\CurrentVersion";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

  if (!isnull(key_h))
  {
    value =  RegQueryValue(handle:key_h, item:"Application Path");
    if (!isnull(value)) path = value[1];
  }
}

RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0);
}
NetUseDel(close:FALSE);


# Grab the file version of TmPfw.exe
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
if ("PCCSRV" >< path)
  exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1Pccnt\Common\TmPfw.exe", string:path);
else
{
  exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1TmPfw.exe", string:path);

  # nb : Reporting client only installs based on
  #      file version of TmPfw.exe could result in FP's.
  #      Therefore we try to get the server version
  #      from a dll file known to indicate correct server
  #      version in use.
  dll   = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1NTSvcRes.dll", string:path);
}

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:exe,
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

# 3. Check if its a OfficeScan client only install,
# if so then get the server version
# from the NTSvcRes.dll.

ver_dll = NULL;
if ("PCCSRV" >!< path)
{
  fh = CreateFile(
    file:dll,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (!isnull(fh))
  {
    ver_dll = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
  }
}

NetUseDel();


# Check the server version number.
if (!isnull(ver_dll))
{
   if(isnull(server_version))
   server_version = string(ver_dll[0],".",ver_dll[1]);
}

if (!isnull(ver))
{
   for (i=0; i < max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (( server_version == "8.0" && ver[0] == 5 && ver[1] == 3 && ver[2] == 0 && ver[3] < 1045)) # OfficeScan 8.0 w/o patch 3191
  {
    if (report_verbosity )
    {
      if ("PCCSRV" >< path) path = string(path,"Pccnt\\Common");

      report = string(
        "\n",
        "Version ", string(ver[0],".",ver[1],".",ver[2],".",ver[3])," of TmPfw.exe\n",
        " is installed under :\n",
        "\n",
        "  ", path,"\n"
      );
      security_hole(port:port,extra:report);
    }
    else security_hole(port);
  }
}
