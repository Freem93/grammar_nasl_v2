#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69832);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/01/28 22:37:18 $");

  script_cve_id(
    "CVE-2013-3160",
    "CVE-2013-3847",
    "CVE-2013-3848",
    "CVE-2013-3849",
    "CVE-2013-3850",
    "CVE-2013-3851",
    "CVE-2013-3852",
    "CVE-2013-3853",
    "CVE-2013-3854",
    "CVE-2013-3855",
    "CVE-2013-3856",
    "CVE-2013-3857",
    "CVE-2013-3858"
  );
  script_bugtraq_id(
    62162,
    62165,
    62168,
    62169,
    62170,
    62171,
    62216,
    62217,
    62220,
    62222,
    62223,
    62224,
    62226
  );
  script_osvdb_id(
    97120,
    97121,
    97122,
    97123,
    97124,
    97125,
    97126,
    97127,
    97128,
    97129,
    97130,
    97132,
    97133
  );
  script_xref(name:"MSFT", value:"MS13-072");
  script_xref(name:"IAVA", value:"2013-A-0178");

  script_name(english:"MS13-072: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (2845537)");
  script_summary(english:"Checks file versions");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The Microsoft Office component installed on the remote host is affected
by multiple remote code execution vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is running a version of Microsoft Office,
Microsoft Word, Office Compatibility Pack, or Microsoft Word Viewer that
is affected by the following remote code execution vulnerabilities :

  - A remote code execution vulnerability exists due to the
    way the XML parser used by Word resolves external
    entities. (CVE-2013-3160)

  - Remote code execution vulnerabilities exist due to
    memory corruption issues in the way that Microsoft
    Office parses files.
    (CVE-2013-3847, CVE-2013-3848, CVE-2013-3849,
    CVE-2013-3850, CVE-2013-3851, CVE-2013-3852,
    CVE-2013-3853, CVE-2013-3854, CVE-2013-3855,
    CVE-2013-3856, CVE-2013-3857, CVE-2013-3858)

If an attacker can trick a user on the affected host into opening a
specially crafted file, it may be possible to leverage these issues to
read arbitrary files on the target system or execute arbitrary code,
subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS13-072");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Office 2003, 2007, 2010,
Office Compatibility Pack, and Microsoft Word Viewer."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");

  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

global_var bulletin, vuln;

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS13-072';
kbs = make_list(
  2597973,
  2760411,
  2760769,
  2760823,
  2767773,
  2767913,
  2817474,
  2817682,
  2817683,
  2845537
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

# Word
kb = "";
installs = get_kb_list("SMB/Office/Word/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/Word/' - '/ProductPath';
    path = installs[install];
    info = "";

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

    # Word 2010
    if (
      ver[0] == 14 && ver[1] == 0 &&
      (
        ver[2] < 7106 ||
        (ver[2] == 7106 && ver[3] < 5001)
      )
    )
    {
      office_sp = get_kb_item("SMB/Office/2010/SP");
      if (!isnull(office_sp) && (office_sp == 1 || office_sp == 2))
      {
        info =
          '\n  Product           : Word 2010' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 14.0.7106.5001' + '\n';
        kb = "2760769";
      }
    }

    # Word 2007
    if (
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6683 ||
        (ver[2] == 6683 && ver[3] < 5001)
      )
    )
    {
      office_sp = get_kb_item("SMB/Office/2007/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        info =
          '\n  Product           : Word 2007' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 12.0.6683.5001' + '\n';
        kb = "2767773";
      }
    }

    # Word 2003
    if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8406)
    {
      office_sp = get_kb_item("SMB/Office/2003/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        info =
          '\n  Product           : Word 2003' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 11.0.8406.0' + '\n';
        kb = "2817682";
      }
    }

    if (info)
    {
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
      vuln = TRUE;
    }
  }
}

# Word Viewer
installs = get_kb_list("SMB/Office/WordViewer/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    info = "";
    version = install - 'SMB/Office/WordViewer/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = "n/a";

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

    if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8406)
    {
      info =
        '\n  Product           : Word Viewer' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 11.0.8406.0' + '\n';
      kb = "2817683";
    }

    if (info)
    {
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
      vuln = TRUE;
      break;
    }
  }
}

# Ensure Office is installed
office_vers = hotfix_check_office_version();
if (!isnull(office_vers))
{
  # Ensure we can get common files directory
  commonfiles = hotfix_get_officecommonfilesdir(officever:"11.0");
  if (commonfiles)
  {
    # Ensure share is accessible
    share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:commonfiles);
    if (is_accessible_share(share:share))
    {
      # Office 2003 SP3
      if (office_vers["11.0"])
      {
        office_sp = get_kb_item("SMB/Office/2003/SP");
        if (!isnull(office_sp) && office_sp == 3)
        {
          path = commonfiles + "\Microsoft Shared\Office11";
          old_report = hotfix_get_report();
          check_file = "Mso.dll";

          if (hotfix_check_fversion(path:path, file:check_file, version:"11.0.8405", min_version:"11.0.0.0") == HCF_OLDER)
          {
            file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + check_file);
            kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
            version = get_kb_item(kb_name);

            info =
              '\n  Product           : Microsoft Office 2003' +
              '\n  File              : ' + path + '\\' + check_file +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : 11.0.8405' + '\n';

            hcf_report = '';
            hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2817474");
            vuln = TRUE;
          }
        }
      }

      # Office 2007 SP3
      if (office_vers["12.0"])
      {
        office_sp = get_kb_item("SMB/Office/2007/SP");
        if (!isnull(office_sp) && office_sp == 3)
        {
          path = commonfiles + "\Microsoft Shared\Office12";
          old_report = hotfix_get_report();
          check_file = "Msptls.dll";

          if (hotfix_check_fversion(path:path, file:check_file, version:"12.0.6682.5000", min_version:"12.0.0.0") == HCF_OLDER)
          {
            file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + check_file);
            kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
            version = get_kb_item(kb_name);

            info =
              '\n  Product           : Microsoft Office 2007 SP3' +
              '\n  File              : ' + path + '\\' + check_file +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : 12.0.6682.5000' + '\n';

            hcf_report = '';
            hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2597973");
            vuln = TRUE;
          }
        }
      }

      # Office 2007 SP3
      if (office_vers["12.0"])
      {
        office_sp = get_kb_item("SMB/Office/2007/SP");
        if (!isnull(office_sp) && office_sp == 3)
        {
          path = commonfiles + "\Microsoft Shared\Office12";
          old_report = hotfix_get_report();
          check_file = "Mso.dll";

          if (hotfix_check_fversion(path:path, file:check_file, version:"12.0.6683.5000", min_version:"12.0.0.0") == HCF_OLDER)
          {
            file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + check_file);
            kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
            version = get_kb_item(kb_name);

            info =
              '\n  Product           : Microsoft Office 2007 SP3' +
              '\n  File              : ' + path + '\\' + check_file +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : 12.0.6683.5000' + '\n';

            hcf_report = '';
            hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2760411");
            vuln = TRUE;
          }
        }
      }

      # Office 2010
      if (office_vers["14.0"])
      {
        office_sp = get_kb_item("SMB/Office/2010/SP");
        if (!isnull(office_sp) && (office_sp == 1 || office_sp == 2))
        {
          path = get_kb_item("SMB/Office/Word/14.0/Path");
          if (path)
          {
            old_report = hotfix_get_report();
            check_file = "Wwlib.dll";

            if (hotfix_check_fversion(path:path, file:check_file, version:"14.0.7106.5001", min_version:"14.0.0.0") == HCF_OLDER)
            {
              file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + check_file);
              kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
              version = get_kb_item(kb_name);
  
              info =
                '\n  Product           : Microsoft Office 2010' +
                '\n  File              : ' + path + '\\' + check_file +
                '\n  Installed version : ' + version +
                '\n  Fixed version     : 14.0.7106.5001' + '\n';
 
              hcf_report = '';
              hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2767913");
              vuln = TRUE;
            }
          }
        }
      }
    }
  }
}

version = '';
installs = get_kb_list("SMB/Office/WordCnv/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/WordCnv/' - '/ProductPath';
    path = installs[install];

    if (path)
    {
      share = hotfix_path2share(path:path);
      if (!is_accessible_share(share:share))
        audit(AUDIT_SHARE_FAIL, share);

      path = path - '\\Wordconv.exe';

      old_report = hotfix_get_report();
      check_file = "wordcnv.dll";

      if (hotfix_check_fversion(path:path, file:check_file, version:"12.0.6683.5001") == HCF_OLDER)
      {
        file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + check_file);
        kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
        kb_name = ereg_replace(pattern:"//"+check_file, replace:"/"+check_file, string:kb_name);
        version = get_kb_item(kb_name);

        info =
          '\n  Product           : Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats' +
          '\n  File              : ' + path + '\\' + check_file +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 12.0.6683.5001' + '\n';

        hcf_report = '';
        hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2760823");
        vuln = TRUE;
      }
    }
  }
}
if (!version)
{
  # Additional check if registry key is missing
  path = hotfix_get_officecommonfilesdir(officever:"12.0") + "\Microsoft Office\Office12";

  kb = "2760823";
  if (
    hotfix_is_vulnerable(file:"wordcnv.dll", version:"12.0.6683.5001", min_version:"12.0.0.0", path:path, bulletin:bulletin, kb:kb)
  ) vuln = TRUE;
}

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
