#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49956);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2016/06/30 19:55:38 $");

  script_cve_id(
    "CVE-2010-2747",
    "CVE-2010-2748",
    "CVE-2010-2750",
    "CVE-2010-3214",
    "CVE-2010-3215",
    "CVE-2010-3216",
    "CVE-2010-3217",
    "CVE-2010-3218",
    "CVE-2010-3219",
    "CVE-2010-3220",
    "CVE-2010-3221"
  );
  script_bugtraq_id(
    43754,
    43760,
    43765,
    43766,
    43767,
    43769,
    43770,
    43771,
    43782,
    43783,
    43784
  );
  script_osvdb_id(
    68574,
    68575,
    68576,
    68577,
    68578,
    68579,
    68580,
    68581,
    68582,
    68583,
    68584
  );
  script_xref(name:"IAVA", value:"2010-A-0145");
  script_xref(name:"MSFT", value:"MS10-079");

  script_name(english:"MS10-079: Vulnerabilities in Microsoft Word Could Allow Remote Code Execution (2293194)");
  script_summary(english:"Checks version of Word");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Word.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of Microsoft Word or Word
Viewer that is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Word file, they could leverage this issue to execute
arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-079");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office XP, 2003, 2007,
2010, Word Viewer, Office Compatibility Pack, and Word Web Apps.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("audit.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-079';
kbs = make_list("2328360", "2344911", "2344993", "2345000", "2345009", "2345043", "2346411");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

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

# Check Office Web Apps
key = "SOFTWARE\Microsoft\Office Server\14.0";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
 value = RegQueryValue(handle:key_h, item:"InstallPath");
 if (!isnull(value))
   owa_path = value[1];

 RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);
NetUseDel (close:FALSE);
hcf_init = TRUE; # Already connected to port 445, mark the session as initialized

info = "";

vuln = FALSE;
kb = "";
# Word
installs = get_kb_list("SMB/Office/Word/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    info = NULL;
    version = install - 'SMB/Office/Word/' - '/ProductPath';
    path = installs[install];

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

    # Word 2010.
    if (
      ver[0] == 14 && ver[1] == 0 &&
      (
        ver[2] <  5123 ||
        (ver[2] == 5123 && ver[3] < 5000)
      )
    )
    {
      office_sp = get_kb_item("SMB/Office/2010/SP");
      if (!isnull(office_sp) && office_sp == 0)
      {
        info =
          '\n  Product           : Word 2010' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 14.0.5123.5000' + '\n';
        kb = "2345000";
      }
    }

    # Word 2007.
    if (
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6545 ||
        (ver[2] == 6545 && ver[3] < 5000)
      )
    )
    {
      office_sp = get_kb_item("SMB/Office/2007/SP");
      if (!isnull(office_sp) && office_sp == 2)
      {
        info =
          '\n  Product           : Word 2007' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 12.0.6545.5000' + '\n';
        kb = "2344993";
      }
    }

    # Word 2003.
    if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8328)
    {
      office_sp = get_kb_item("SMB/Office/2003/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        info =
          '\n  Product           : Word 2003' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 11.0.8328.0' + '\n';
        kb = "2344911";
      }
    }

    # Word 2002.
    if (ver[0] == 10 && ver[1] == 0 && ver[2] < 6866)
    {
      office_sp = get_kb_item("SMB/Office/XP/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        info =
          '\n  Product           : Word 2002' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 10.0.6866.0' + '\n';
        kb = "2328360";
      }
    }

    if (info)
    {
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
      vuln = TRUE;
    }
  }
}


# Word Viewer.
installs = get_kb_list("SMB/Office/WordViewer/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    info = NULL;
    version = install - 'SMB/Office/WordViewer/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = 'n/a';

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

    # Word Viewer 2003.
    if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8328)
    {
      info =
        '\n  Product           : Word Viewer 2003' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 11.0.8328.0' + '\n';
      kb = "2345009";
    }

    if (info)
    {
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
      vuln = TRUE;
      break;
    }
  }
}

# 2007 Microsoft Office system and the Microsoft Office Compatibility Pack.
installs = get_kb_list("SMB/Office/WordCnv/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    info = NULL;
    version = install - 'SMB/Office/WordCnv/' - '/ProductPath';
    path = installs[install];

    share = hotfix_path2share(path:path);
    if (is_accessible_share(share:share))
    {
      path = path - '\\Wordconv.exe';

      old_report = hotfix_get_report();
      file = "wordcnv.dll";

      if (hotfix_check_fversion(path:path, file:file, version:"12.0.6545.5000") == HCF_OLDER)
      {
        file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + file);
        kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
        version = get_kb_item(kb_name);

        info =
          '\n  Product           : Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats' +
          '\n  File              : ' + path + '\\' + file +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 12.0.6545.5000' + '\n';

        hcf_report = '';
        hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2345043");
        vuln = TRUE;
      }
    }
  }
}

# Office Web Apps 2010
if (owa_path)
{
  share = owa_path[0] + '$';
  if (is_accessible_share(share:share))
  {
    owa_path = owa_path + "\WebServices\ConversionService\Bin\Converter";
    old_report = hotfix_get_report();

    if (hotfix_is_vulnerable(file:"msoserver.dll", version:"14.0.5120.5000", min_version:"14.0.0.0", path:owa_path))
    {
      file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:owa_path, replace:"\1\msoserver.dll");
      kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
      version = get_kb_item(kb_name);

      info =
       '\n  Product           : Office Web Apps 2010' +
       '\n  File              : ' + owa_path + '\\msoserver.dll' +
       '\n  Installed version : ' + version +
       '\n  Fixed version     : 14.0.5120.5000' + '\n';

      hcf_report = '';
      hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2346411");
      vuln = TRUE;
    }
  }
  else debug_print('is_accessible_share() failed on ' + owa_path);
}

hotfix_check_fversion_end();

if (vuln)
{
    set_kb_item(name:'SMB/Missing/MS10-079', value:TRUE);
    hotfix_security_hole();
    exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
