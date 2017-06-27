#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53379);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2011-0655", "CVE-2011-0656", "CVE-2011-0976");
  script_bugtraq_id(46228, 47251, 47252);
  script_osvdb_id(71769, 71770, 71771);
  script_xref(name:"IAVA", value:"2011-A-0047");
  script_xref(name:"MSFT", value:"MS11-022");

  script_name(english:"MS11-022: Vulnerabilities in Microsoft PowerPoint Could Allow Remote Code Execution (2489283)");
  script_summary(english:"Checks version of PowerPoint");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
PowerPoint.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of Microsoft PowerPoint that is
affected by multiple code execution vulnerabilities. A remote attacker
could exploit this by tricking a user into viewing a maliciously
crafted PowerPoint file.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-044/");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-022");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for PowerPoint 2002, 2003,
2007, 2010, PowerPoint Viewer 2007 and 2010, Office Compatibility
Pack, and Office Web Apps.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint_viewer");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS11-022';
kbs = make_list("2464588", "2464594", "2464617", "2464623", "2464635", "2519975", "2519984", "2520047");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


# PowerPoint.
info = "";



# First check office web apps
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

owa_path = NULL;

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
NetUseDel();

if (owa_path)
{
  share = owa_path[0] + '$';
  if (is_accessible_share(share:share))
  {
    kb = '2520047';
    owa_path = owa_path + "\WebServices\ConversionService\Bin\Converter";

    if (hotfix_is_vulnerable(file:"msoserver.dll", version:"14.0.5136.5002", min_version:"14.0.0.0", path:owa_path, bulletin:bulletin, kb:kb))
    {
      file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:owa_path, replace:"\1\msoserver.dll");
      kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
      version = get_kb_item(kb_name);

      info =
        '\n  Product           : Office Web Apps 2010' +
        '\n  Path              : ' + owa_path + '\\msoserver.dll' +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 14.0.5136.5002' + '\n';

      hcf_report = '';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
      vuln = TRUE;
    }
  }
  else debug_print('is_accessible_share() failed on ' + owa_path);
}

# Check powerpoint versions
installs = get_kb_list("SMB/Office/PowerPoint/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/PowerPoint/' - '/ProductPath';
    path = installs[install];

    info = NULL;
    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # PowerPoint 2010
    if (ver[0] == 14 && path != 'n/a')
    {
      office_sp = get_kb_item("SMB/Office/2010/SP");
      if (!isnull(office_sp) && office_sp == 0)
      {
        kb = '2519975';
        path = ereg_replace(pattern:"^([A-Za-z]:.*)\\PowerPnt.exe", string:path, replace:"\1");
        share = hotfix_path2share(path:path);

        if (is_accessible_share(share:share))
        {
          old_report = hotfix_get_report();

          if (hotfix_is_vulnerable(file:"ppcore.dll", version:"14.0.5136.5003", min_version:"14.0.0.0", path:path, bulletin:bulletin, kb:kb))
          {
            file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\ppcore.dll");
            kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
            version = get_kb_item(kb_name);

            info =
              '\n  Product           : PowerPoint 2010' +
              '\n  Path              : ' + path + '\\ppcore.dll' +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : 14.0.5136.5003\n';
          }
        }
        else debug_print('is_accessible_share() failed on ' + path);
      }
    }

    # PowerPoint 2007.
    else if (ver[0] == 12 && path != 'n/a')
    {
      office_sp = get_kb_item("SMB/Office/2007/SP");
      if (!isnull(office_sp) && office_sp == 2)
      {
        kb = "2464594";
        path = ereg_replace(pattern:"^([A-Za-z]:.*)\\PowerPnt.exe", string:path, replace:"\1");
        share = hotfix_path2share(path:path);
        share = path[0] + '$';

        if (is_accessible_share(share:share))
        {
          old_report = hotfix_get_report();

          if (hotfix_is_vulnerable(file:"ppcore.dll", version:"12.0.6550.5000", min_version:"12.0.0.0", path:path, bulletin:bulletin, kb:kb))
          {
            file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\ppcore.dll");
            kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
            version = get_kb_item(kb_name);

            info =
              '\n  Product           : PowerPoint 2007' +
              '\n  Path              : ' + path + '\\ppcore.dll' +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : 12.0.6550.5000\n';
            hotfix_check_fversion_end();
          }
        }
        else debug_print('is_accessible_share() failed on ' + path);
      }
    }
    # PowerPoint 2003.
    else if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8334)
    {
      office_sp = get_kb_item("SMB/Office/2003/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        kb = "2464588";
        info =
          '\n  Product           : PowerPoint 2003\n' +
          '  File              : ' + path + '\n' +
          '  Installed version : ' + version + '\n' +
          '  Fixed version     : 11.0.8334.0\n';
      }
    }
    # PowerPoint 2002.
    else if (ver[0] == 10 && ver[1] == 0 && ver[2] < 6868)
    {
      office_sp = get_kb_item("SMB/Office/XP/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        kb = "2464617";
        info =
          '\n  Product           : PowerPoint 2002\n' +
          '  File              : ' + path + '\n' +
          '  Installed version : ' + version + '\n' +
          '  Fixed version     : 10.0.6868.0\n';
      }
    }

    if (info)
    {
      hcf_report = '';
      hotfix_add_report(old_report + info, bulletin:bulletin, kb:kb);
      vuln = TRUE;
    }
  }
}


# PowerPoint Viewer.
installs = get_kb_list("SMB/Office/PowerPointViewer/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/PowerPointViewer/' - '/ProductPath';
    path = installs[install];

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # Office PowerPoint Viewer 2010
    if (
      ver[0] == 14 && ver[1] == 0 &&
      (
        ver[2] < 5136 ||
        (ver[2] == 5136 && ver[3] < 5003)
      )
    )
    {
      kb = "2519984";
      info =
        '\n  Product           : PowerPoint Viewer 2010\n' +
        '  File              : ' + path + '\n' +
        '  Installed version : ' + version + '\n' +
        '  Fixed version     : 14.0.5136.5003\n';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
      vuln = TRUE;
    }
    # PowerPoint Viewer 2007.
    else if (
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6550 ||
        (ver[2] == 6550 && ver[3] < 5000)
      )
    )
    {
      kb = "2464623";
      info =
        '\n  Product           : PowerPoint Viewer 2007\n' +
        '  File              : ' + path + '\n' +
        '  Installed version : ' + version + '\n' +
        '  Fixed version     : 12.0.6550.5000\n';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
      vuln = TRUE;
    }
  }
}


# PowerPoint Converter.
installs = get_kb_list("SMB/Office/PowerPointCnv/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/PowerPointCnv/' - '/ProductPath';
    path = installs[install];

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    path = ereg_replace(pattern:"^([A-Za-z]:.*)\\Ppcnvcom.exe", string:path, replace:"\1");
    info = NULL;

    #  PowerPoint 2007 converter.
    if (ver[0] == 12 && path)
    {
      kb = "2464635";
      share = path[0] + '$';

      if (is_accessible_share(share:share))
      {
        old_report = hotfix_get_report();

        if (hotfix_is_vulnerable(file:"ppcnv.dll", version:"12.0.6550.5000", min_version:"12.0.0.0", path:path, bulletin:bulletin, kb:kb))
        {
          file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\ppcnv.dll");
          kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
          version = get_kb_item(kb_name);

          vuln = TRUE;
          info =
            '\n  Product           : PowerPoint 2007 Converter' +
            '\n  Path              : ' + path + '\\ppcnv.dll' +
            '\n  Installed version : ' + version +
            '\n  Fixed version     : 12.0.6550.5000\n';
          hcf_report = '';
          hotfix_add_report(old_report + info, bulletin:bulletin, kb:kb);
        }
      }
      else debug_print('is_accessible_share() failed on ' + path);
    }
  }
}

hotfix_check_fversion_end();

# report if office webapps, powerpoint converter, or powerpoint viewer
# are unpatched
if (vuln)
{
  set_kb_item(name:"SMB/Missing/" + bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
