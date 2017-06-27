#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55593);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/12 17:12:49 $");

  script_bugtraq_id(48638);
  script_osvdb_id(74328);

  script_name(english:"Trend Micro Control Manager CasLogDirectInsertHandler.cs Remote Code Execution");
  script_summary(english:"Checks file version of TMCM's Common.NET.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web application that allows remote
code execution.");
  script_set_attribute(attribute:"description", value:
"The Trend Micro Control Manager install on the remote Windows host is
missing Critical Patch 1422. As such, the included
Cas_LogDirectInsert.aspx http handler reportedly has a vulnerability
by which malicious XML and schema information can be used in queries
in the backend database.

Using a specially crafted POST request, an unauthenticated, remote
attacker could reportedly leverage this issue to create and insert a
user account that can in turn be used to execute remote code through
the management console.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-234");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/518822/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://esupport.trendmicro.com/solution/en-us/1058280.aspx"
  );
  # http://www.trendmicro.com/ftp/documentation/readme/readme_critical_patch_TMCM55_1422.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3e94ba65"
  );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Trend Micro Control Manager 5.5 if necessary and apply
Critical Patch 1422.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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


# Grab the file version of Common.NET.dll.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to "+share+" share.");
}


errmsg = '';
fixed_version = "5.5.0.1422";
info = '';
vuln_dlls = 0;

foreach subdir (make_list("\", "\WebUI\WebApp\Bin\"))
{
  dll = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1"+subdir+"Common.NET.dll", string:path);

  fh = CreateFile(
    file:dll,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);

    if (isnull(ver))
    {
      errmsg += '\n  - Can\'t get the file version from ' + (share-'$')+':'+dll;
    }
    else if (ver_compare(ver:ver, fix:fixed_version) == -1)
    {
      vuln_dlls++;

      info +=
        '\n  File              : ' + (share-'$')+':'+dll +
        '\n  Installed version : ' + join(ver, sep:'.') +
        '\n  Fixed version     : ' + fixed_version + '\n';
    }
  }
}
NetUseDel();


if (info)
{
  if (report_verbosity > 0)
  {
   if (vuln_dlls == 1) s = ' was';
    else s = 's were';

    report = '\n' + 'The following unpatched file'+s+' found on the remote host :' +
             '\n' +
             info;

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else
{
  if (errmsg) exit(1, errmsg);
  else exit(0, "The Trend Micro Control Manager install in '"+path+"' is not affected.");
}
