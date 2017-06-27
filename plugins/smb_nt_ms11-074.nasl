#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56177);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/01/28 22:37:17 $");

  script_cve_id(
    "CVE-2011-0653",
    "CVE-2011-1252",
    "CVE-2011-1890",
    "CVE-2011-1891",
    "CVE-2011-1892",
    "CVE-2011-1893"
  );
  script_bugtraq_id(
    48199,
    49002,
    49004,
    49005,
    49010,
    49511,
    49620
  );
  script_osvdb_id(72944, 75381, 75389, 75390, 75391, 75393, 75394);
  script_xref(name:"EDB-ID", value:"17873");
  script_xref(name:"IAVB", value:"2011-B-0115");
  script_xref(name:"MSFT", value:"MS11-074");

  script_name(english:"MS11-074: Vulnerabilities in Microsoft SharePoint Could Allow Elevation of Privilege (2451858)");
  script_summary(english:"Checks SharePoint / Groove / Office Web Apps version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple privilege escalation and
information disclosure vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of SharePoint Services, SharePoint Server, Groove, or
Office Web Apps installed on the remote host has multiple privilege
escalation and information disclosure vulnerabilities.

A remote attacker could exploit them by tricking a user into making a
malicious request, resulting in arbitrary script code execution.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/519624");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-074");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SharePoint Server 2007,
SharePoint Server 2010, SharePoint Workspace 2010, SharePoint
Foundation 2010, Office Groove 2007, Office Forms Server 2007, Office
Groove Server 2007, Office Groove Data Bridge Server 2007, Office
Groove Management Server 2007, Groove Server 2010, Windows SharePoint
Services 2.0, Windows SharePoint Services 3.0, Office Web Apps 2010,
and Word Web App 2010.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:forms_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:groove");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:groove_data_bridge_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:groove_management_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:groove_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_services");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_workspace");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");



get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS11-074';
kbs = make_list("2493987", "2494001", "2494007", "2494022", "2508964", "2508965", "2552997", "2552998", "2552999", "2553001", "2560885", "2566445", "2566449", "2566450", "2566954", "2566958");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/WindowsVersion");

global_var hklm;

function get_key(attr, key)
{
  local_var item, key_h, value;

  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (isnull(key_h))
    return NULL;

  item = RegQueryValue(handle:key_h, item:attr);
  if (!isnull(item))
    value = item[1];

  RegCloseKey(handle:key_h);

  return value;
}

function get_ver(base, file)
{
  local_var handle, path, r, share, ver;

  if (isnull(base))
    return NULL;

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:base);
  path = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\" + file, string:base);
  ver = NULL;

  r = NetUseAdd(share:share);
  if (r != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to '" + share + "' share.");
  }

  handle = CreateFile(
    file               : path,
    desired_access     : GENERIC_READ,
    file_attributes    : FILE_ATTRIBUTE_NORMAL,
    share_mode         : FILE_SHARE_READ,
    create_disposition : OPEN_EXISTING
  );
  if (!isnull(handle))
  {
    ver = GetFileVersion(handle:handle);
    CloseFile(handle:handle);
  }

  NetUseDel(close:FALSE);

  return ver;
}

# Get credentials and connection information.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

# Connect to IPC share.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

# Get path information for SharePoint Services or Foundation.
foreach ver (make_list("6.0", "12.0", "14.0"))
{
  spsvc_path = get_key(
    key  : "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\" + ver,
    attr : "Location"
  );

  if (!isnull(spsvc_path))
    break;
}

# Get path information for Groove 2007.
g_path = get_key(
  key  : "SOFTWARE\Microsoft\Office\12.0\Groove\InstallRoot",
  attr : "Path"
);

# Get path information for Groove Server 2007 Data Bridge.
gdb_path = get_key(
  key  : "SOFTWARE\Microsoft\Office Server\12.0\Groove",
  attr : "InstallRoot"
);

# Get path information for IIS webroot (needed for Groove Management
# Server 2007/2010).
gms_path = get_key(
  key  : "SOFTWARE\Microsoft\InetStp",
  attr : "PathWWWRoot"
);
if ("%systemdrive%" >< tolower(gms_path))
{
  root = hotfix_get_systemroot();
  gms_path = root[0] + ":" + substr(gms_path, strlen("%systemdrive%"));
}

# Get path information for SharePoint Workspace.
spws_path = get_key(
  key  : "SOFTWARE\Microsoft\Office\14.0\Groove\InstallRoot",
  attr : "Path"
);

# Get path information for SharePoint Server 2007.
sps_2007_path = get_key(
  key  : "SOFTWARE\Microsoft\Office Server\12.0",
  attr : "InstallPath"
);

# Get path information for SharePoint Server 2010.
sps_2010_path = get_key(
  key  : "SOFTWARE\Microsoft\Office Server\14.0",
  attr : "InstallPath"
);

# Get path information for Office Web Apps.
owa_path = sps_2010_path;

# Get path information for Word 2010 Web Apps, which is technically
# Word Automation Services for SharePoint Server 2010.
wwa_path = sps_2010_path;

# Get path information for Office Form Server 2007.
ofs_path = sps_2007_path;

# Get path information for SharePoint Server 2010 OSRV and WOSRV.
osrv_path = get_key(
  key  : "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\14.0",
  attr : "Location"
);

# Get path information for SharePoint Server 2010 DLC.
dlc_path = osrv_path;

# Get path information for KB2566958.
kb2566958_path = osrv_path;

# Close connection to registry.
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

# Get version information for SharePoint Services and Foundation.
spsvc_file = "ISAPI\Owssvr.dll";
spsvc_ver = get_ver(base:spsvc_path, file:spsvc_file);

# Get version information for Groove 2007.
g_file = "GrooveUtil.dll";
g_ver = get_ver(base:g_path, file:g_file);

# Get version information for Groove Server 2007 Data Bridge.
gdb_file = "bin\GrooveUtil.dll";
gdb_ver = get_ver(base:gdb_path, file:gdb_file);

# Get version information for Groove Management Server 2007.
gms_file = "GMS\bin\Groove.management.server.dll";
gms_ver = get_ver(base:gms_path, file:gms_file);

if (isnull(gms_ver))
{
  # Get version information for Groove Management Server 2007.
  gms_file = "GMS14\Admin\bin\Groove.management.server.dll";
  gms_ver = get_ver(base:gms_path, file:gms_file);
}

# Get version information for SharePoint Workspace.
spws_file = "Groove.exe";
spws_ver = get_ver(base:spws_path, file:spws_file);

# Get version information for SharePoint Server 2007
sps_2007_file = "Bin\Microsoft.sharepoint.publishing.dll";
sps_2007_ver = get_ver(base:sps_2007_path, file:sps_2007_file);

# Get version information for SharePoint Server 2010.
sps_2010_file = "Bin\Microsoft.sharepoint.publishing.dll";
sps_2010_ver = get_ver(base:sps_2010_path, file:sps_2010_file);

# Get version for Office 2010 Web Apps.
owa_file = "WebServices\ConversionService\Bin\Converter\sword.dll";
owa_ver = get_ver(base:owa_path, file:owa_file);

# Get version for Word 2010 Web Apps, which is technically Word
# Automation Services for SharePoint Server 2010.
wwa_file = "WebServices\WordServer\Core\sword.dll";
wwa_ver = get_ver(base:wwa_path, file:wwa_file);

# Get version information for SharePoint Server 2007, SharePoint
# Server 2007 for Search, and Office Forms Server 2007. KB2553001,
# KB2553002, and KB2553005 refer to this file as "Pidval.exe", but in
# we found it to instead be named "Pidvalidator.exe". We'll check both
# to be on the safe side.
ofs_file = "Bin\Pidvalidator.exe";
ofs_ver = get_ver(base:ofs_path, file:ofs_file);

if (isnull(ofs_ver))
{
  ofs_file = "Bin\Pidval.exe";
  ofs_ver = get_ver(base:ofs_path, file:ofs_file);
}

# Get version for SharePoint Server 2010 OSRV and WOSRV.
osrv_file = "ISAPI\Microsoft.Office.Server.dll";
osrv_ver = get_ver(base:osrv_path, file:osrv_file);

# Get version for SharePoint Server 2010 DLC.
dlc_file = "ISAPI\Microsoft.office.policy.dll";
dlc_ver = get_ver(base:dlc_path, file:dlc_file);

# Get version for KB2566456.
kb2566958_file = "ISAPI\Microsoft.sharepoint.client.dll";
kb2566958_ver = get_ver(base:kb2566958_path, file:kb2566958_file);

# Close connection to server.
NetUseDel();



######################################################################
# Windows SharePoint Services
# ---------------------------
# [KB2494007] v2: Owssvr.dll (11.0.8339.0)
# [KB2493987] v3: Owssvr.dll (12.0.6565.5001)
#
#
# Microsoft SharePoint Foundation 2010
# ------------------------------------
# [KB2494001] Owssvr.dll (14.0.6106.5008)
######################################################################
if (!isnull(spsvc_ver))
{
  fix = NULL;

  if (spsvc_ver[0] == 11)
  {
    name = "Windows SharePoint Services";
    fix = "11.0.8339.0";
    kb = "2494007";
  }
  else if (spsvc_ver[0] == 12)
  {
    name = "Windows SharePoint Services";
    fix = "12.0.6565.5001";
    kb = "2493987";
  }
  else if (spsvc_ver[0] == 14)
  {
    name = "Microsoft SharePoint Foundation 2010";
    fix = "14.0.6106.5008";
    kb = "2494001";
  }

  spsvc_ver = join(spsvc_ver, sep:".");
  if (!isnull(fix) && ver_compare(ver:spsvc_ver, fix:fix) < 0)
  {
    info =
      '\n  Product           : ' + name +
      '\n  Path              : ' + spsvc_path + spsvc_file +
      '\n  Installed version : ' + spsvc_ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
    vuln = TRUE;
  }
}

######################################################################
# Microsoft Groove 2007
# ---------------------
# [KB2552997] Grooveutil.dll (12.0.6562.5000)
######################################################################
if (!isnull(g_ver))
{
  name = "Groove 2007";
  fix = "12.0.6562.5000";
  kb = "2552997";

  g_ver = join(g_ver, sep:".");
  if (ver_compare(ver:g_ver, fix:fix) < 0)
  {
    info =
      '\n  Product           : ' + name +
      '\n  Path              : ' + g_path + g_file +
      '\n  Installed version : ' + g_ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
    vuln = TRUE;
  }
}

######################################################################
# Microsoft Groove Server 2007 Data Bridge
# ----------------------------------------
# [KB2552999] Grooveutil.dll (4.2.2.2827)
######################################################################
if (!isnull(gdb_ver))
{
  name = "Groove Server 2007 Data Bridge";
  fix = "4.2.2.2827";
  kb = "2552999";

  gdb_ver = join(gdb_ver, sep:".");
  if (ver_compare(ver:gdb_ver, fix:fix) < 0)
  {
    info =
      '\n  Product           : ' + name +
      '\n  Path              : ' + gdb_path + gdb_file +
      '\n  Installed version : ' + gdb_ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
    vuln = TRUE;
  }
}

######################################################################
# Microsoft Groove Management Server
# ----------------------------------
# [KB2552998] 2007: Groove.management.server.dll (4.2.2.2827)
# [KB2508965] 2010: Groove.management.server.dll (14.0.6106.5000)
######################################################################
if (!isnull(gms_ver))
{
  fix = NULL;

  if (gms_ver[0] == 14)
  {
    name = "Groove Management Server 2010";
    fix = "14.0.6106.5000";
    kb = "2508965";
  }
  else if (gms_ver[0] < 14)
  {
    name = "Groove Management Server 2007";
    fix = "4.2.2.2827";
    kb = "2552998";
  }

  gms_ver = join(gms_ver, sep:".");
  if (!isnull(fix) && ver_compare(ver:gms_ver, fix:fix) < 0)
  {
    info =
      '\n  Product           : ' + name +
      '\n  Path              : ' + gms_path + "\" + gms_file +
      '\n  Installed version : ' + gms_ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
    vuln = TRUE;
  }
}

######################################################################
# Microsoft SharePoint Workspace 2010
# -----------------------------------
# [KB2566445] Groove.exe (14.0.6106.5000)
######################################################################
if (!isnull(spws_ver))
{
  name = "SharePoint Workspace 2010";
  fix = "14.0.6106.5000";
  kb = "2566445";

  spws_ver = join(spws_ver, sep:".");
  if (ver_compare(ver:spws_ver, fix:fix) < 0)
  {
    info =
      '\n  Product           : ' + name +
      '\n  Path              : ' + spws_path + spws_file +
      '\n  Installed version : ' + spws_ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
    vuln = TRUE;
  }
}

######################################################################
# Microsoft Office SharePoint Server 2007
# ---------------------------------------
# [KB2508964] Microsoft.sharepoint.publishing.dll (12.0.6555.5000)
######################################################################
if (!isnull(sps_2007_ver))
{
  name = "SharePoint Server 2007";
  fix = "12.0.6555.5000";
  kb = "2508964";

  sps_2007_ver = join(sps_2007_ver, sep:".");
  if (ver_compare(ver:sps_2007_ver, fix:fix) < 0)
  {
    info =
      '\n  Product           : ' + name +
      '\n  Path              : ' + sps_2007_path + sps_2007_file +
      '\n  Installed version : ' + sps_2007_ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
    vuln = TRUE;
  }
}

######################################################################
# Microsoft Office SharePoint Server 2010
# ---------------------------------------
# [KB2494022] Microsoft.sharepoint.publishing.dll (14.0.6106.5001)
######################################################################
if (!isnull(sps_2010_ver))
{
  name = "SharePoint Server 2010";
  fix = "14.0.6106.5001";
  kb = "2494022";

  sps_2010_ver = join(sps_2010_ver, sep:".");
  if (ver_compare(ver:sps_2010_ver, fix:fix) < 0)
  {
    info =
      '\n  Product           : ' + name +
      '\n  Path              : ' + sps_2010_path + sps_2010_file +
      '\n  Installed version : ' + sps_2010_ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
    vuln = TRUE;
  }
}

######################################################################
# Microsoft Office 2010 Web Apps
# ------------------------------
# [KB2566449] sword.dll (14.0.6106.5000)
######################################################################
if (!isnull(owa_ver))
{
  name = "Microsoft Office 2010 Web Apps";
  fix = "14.0.6106.5000";
  kb = "2566449";

  owa_ver = join(owa_ver, sep:".");
  if (ver_compare(ver:owa_ver, fix:fix) < 0)
  {
    info =
      '\n  Product           : ' + name +
      '\n  Path              : ' + owa_path + owa_file +
      '\n  Installed version : ' + owa_ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
    vuln = TRUE;
  }
}

######################################################################
# Microsoft Word Web Application 2010
# -----------------------------------
# [KB2566450] sword.dll (14.0.6106.5000)
######################################################################
if (!isnull(wwa_ver))
{
  name = "Microsoft Word Web Application 2010";
  fix = "14.0.6106.5000";
  kb = "2566450";

  wwa_ver = join(wwa_ver, sep:".");
  if (ver_compare(ver:wwa_ver, fix:fix) < 0)
  {
    info =
      '\n  Product           : ' + name +
      '\n  Path              : ' + wwa_path + wwa_file +
      '\n  Installed version : ' + wwa_ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
    vuln = TRUE;
  }
}

######################################################################
# Microsoft Groove Server 2007
# ----------------------------
# [KB2553001] Pidval.exe (12.0.6562.5000)
#
#
# Microsoft Groove Server 2007 for Search
# ---------------------------------------
# [KB2553002] Pidval.exe (12.0.6562.5000)
#
#
# Microsoft Office Forms Server 2007
# ----------------------------------
# [KB2553005] Pidval.exe (12.0.6562.5000)
######################################################################
if (!isnull(ofs_ver))
{
  # XXX-TODO: Need to fix the name and KB later to distinguish between
  # the three possibilities above.
  name = "SharePoint Server 2007 / Office Forms Server 2007";
  fix = "12.0.6562.5000";
  kb = "2553001";

  ofs_ver = join(ofs_ver, sep:".");
  if (ofs_ver =~ "^12\.0" && ver_compare(ver:ofs_ver, fix:fix) < 0)
  {
    info =
      '\n  Product           : ' + name +
      '\n  Path              : ' + ofs_path + ofs_file +
      '\n  Installed version : ' + ofs_ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
    vuln = TRUE;
  }
}

######################################################################
# Microsoft SharePoint Server 2010
# --------------------------------
# [KB2560885]  OSRV: Microsoft.office.server.dll (14.0.6106.5001)
# [KB2566960] WOSRV: Microsoft.office.server.dll (14.0.6106.5001)
######################################################################
if (!isnull(osrv_ver))
{
  # XXX-TODO: Need to fix the name and KB later to distinguish between
  # the two possibilities above.
  name = "SharePoint Server 2010 OSRV / WOSRV";
  fix = "14.0.6106.5001";
  kb = "2560885";

  osrv_ver = join(osrv_ver, sep:".");
  if (ver_compare(ver:osrv_ver, fix:fix) < 0)
  {
    info =
      '\n  Product           : ' + name +
      '\n  Path              : ' + osrv_path + osrv_file +
      '\n  Installed version : ' + osrv_ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
    vuln = TRUE;
  }
}

######################################################################
# Microsoft SharePoint Server 2010 Document Lifecycle Components
# --------------------------------------------------------------
# [KB2566954] Microsoft.office.policy.dll (14.0.6106.5001)
######################################################################
if (!isnull(dlc_ver))
{
  name = "SharePoint Server 2010 Document Lifecycle Components";
  fix = "14.0.6106.5001";
  kb = "2566954";

  dlc_ver = join(dlc_ver, sep:".");
  if (ver_compare(ver:dlc_ver, fix:fix) < 0)
  {
    info =
      '\n  Product           : ' + name +
      '\n  Path              : ' + dlc_path + dlc_file +
      '\n  Installed version : ' + dlc_ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
    vuln = TRUE;
  }
}

######################################################################
# Microsoft SharePoint Server 2010
# --------------------------------
# [KB2566958] Microsoft.sharepoint.client.dll (14.0.6106.5001)
######################################################################
if (!isnull(kb2566958_ver))
{
  name = "SharePoint Server 2010";
  fix = "14.0.6106.5001";
  kb = "2566958";

  kb2566958_ver = join(kb2566958_ver, sep:".");
  if (ver_compare(ver:kb2566958_ver, fix:fix) < 0)
  {
    info =
      '\n  Product           : ' + name +
      '\n  Path              : ' + kb2566958_path + kb2566958_file +
      '\n  Installed version : ' + kb2566958_ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
    vuln = TRUE;
  }
}

hotfix_check_fversion_end();

if (!vuln)
  exit(0, "The host is not affected");

# Flag the system as vulnerable.
set_kb_item(name:"SMB/Missing/" + bulletin, value:TRUE);
set_kb_item(name:"www/0/XSS", value:TRUE);
hotfix_security_warning();
