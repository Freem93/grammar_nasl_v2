#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57062);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/23 20:42:24 $");

  script_cve_id("CVE-2011-5001");
  script_bugtraq_id(50965);
  script_osvdb_id(77585);
  script_xref(name:"EDB-ID", value:"18514");

  script_name(english:"Trend Micro Control Manager CmdProcessor.exe Remote Buffer Overflow");
  script_summary(english:"Checks file version of TMCM's cmdHandlerRedAlertController.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web application that allows remote
code execution.");
  script_set_attribute(attribute:"description", value:
"The Trend Micro Control Manager install on the remote Windows host is
missing Critical Patch 1613. As such, the included CmdProcessor.exe
component is affected by a remote stack-based buffer overflow
vulnerability in the 'CGenericScheduler::AddTask' function of
cmdHandlerRedAlertController.dll. By sending a specially crafted IPC
packet to the service, which listens by default on TCP port 20101, an
unauthenticated, remote attacker could leverage this issue to execute
arbitrary code in the context of the user under which the service
runs, which is SYSTEM by default.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-345");
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/fulldisclosure/2011/Dec/204"
  );
  # http://www.trendmicro.com/ftp/documentation/readme/readme_critical_patch_TMCM55_1613.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a60584c"
  );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Trend Micro Control Manager 5.5 if necessary and apply
Critical Patch 1613.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'TrendMicro Control Manger CmdProcessor.exe Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");


get_kb_item_or_exit("SMB/Registry/Enumerated");


# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');


# Connect to remote registry.
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


# Figure out where it is installed.
path = NULL;

key = "SOFTWARE\TrendMicro\TVCS";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"HomeDirectory");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "Trend Micro Control Manager is not installed.");
}
NetUseDel(close:FALSE);


# Grab the file version of cmdHandlerRedAlertController.dll.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to "+share+" share.");
}

dll = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\cmdHandlerRedAlertController.dll", string:path);
fh = CreateFile(
  file:dll,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(fh))
{
  NetUseDel();
  exit(0, "Failed to open '"+(share-'$')+":"+dll+"'.");
}

ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();


if (isnull(ver))
{
  exit(1, "Couldn't get the version number from '"+(share-'$')+":"+dll+"'.");
}

fixed_version = "5.5.0.1613";
version = join(ver, sep:'.');

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  File              : ' + (share-'$')+':'+dll +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The Trend Micro Control Manager install in '"+path+"' includes cmdHandlerRedAlertController.dll file version "+version+" and thus is not affected.");
