#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57280);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/07/11 14:12:52 $");

  script_cve_id("CVE-2011-3396", "CVE-2011-3413");
  script_bugtraq_id(50964, 50967);
  script_osvdb_id(77664, 77668);
  script_xref(name:"IAVA", value:"2011-A-0166");
  script_xref(name:"MSFT", value:"MS11-094");

  script_name(english:"MS11-094: Vulnerabilities in Microsoft PowerPoint Could Allow Remote Code Execution (2639142)");
  script_summary(english:"Checks Ppcore.dll / Ppcnv.dll / PowerPointViewer version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through Microsoft
PowerPoint."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host has a version of Microsoft PowerPoint that is
affected by multiple vulnerabilities :

  - The application insecurely restricts the path used for
    loading external DLL files. This could lead to
    arbitrary code execution. (CVE-2011-3396)

  - The application could cause memory to be corrupted when
    reading an invalid record in a specially crafted
    PowerPoint file. (CVE-2011-3413)

If a remote attacker can trick a user into opening a malicious
PowerPoint file using the affected install, either vulnerability can
be leveraged to execute arbitrary code subject to the user's
privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-094");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for PowerPoint 2007 and 2010,
PowerPoint Viewer 2007, and Office Compatibility Pack."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");

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

bulletin = 'MS11-094';
kbs = make_list("2553185", "2596764", "2596843", "2596912");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


vuln = FALSE;


# Check PowerPoint versions.
installs = get_kb_list("SMB/Office/PowerPoint/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/PowerPoint/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = 'n/a';
    info = "";
    old_report = hotfix_get_report();

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # PowerPoint 2010
    office_sp2010 = get_kb_item("SMB/Office/2010/SP");
    office_sp2007 = get_kb_item("SMB/Office/2007/SP");
    if ((!isnull(office_sp2010) && office_sp2010 == 0) && (ver[0] == 14 && ver[1] == 0 && ver[2] < 6009))
    {
      kb = "2553185";
      fixed_version = "14.0.6111.5000";

      if (path != 'n/a')
      {
        path = ereg_replace(pattern:"^([A-Za-z]:.*)\\PowerPnt.exe", string:path, replace:"\1");
        share = hotfix_path2share(path:path);

        if (is_accessible_share(share:share))
        {
          if (hotfix_is_vulnerable(file:"ppcore.dll", version:fixed_version, min_version:"14.0.0.0", path:path, bulletin:bulletin, kb:kb))
          {
            file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\ppcore.dll");
            kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
            version = get_kb_item(kb_name);

            info =
              '\n  Product           : PowerPoint 2010' +
              '\n  Path              : ' + path + '\\ppcore.dll' +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : ' + fixed_version + '\n';
          }
        }
      }
    }

    # PowerPoint 2007 (not SP3)
    else if ((!isnull(office_sp2007) && office_sp2007 == 2) && (ver[0] == 12 && ver[1] == 0 && ver[2] < 6600))
    {
      kb = "2596764";
      fixed_version = "12.0.6654.5000";

      if (path != 'n/a')
      {
        path = ereg_replace(pattern:"^([A-Za-z]:.*)\\PowerPnt.exe", string:path, replace:"\1");
        share = hotfix_path2share(path:path);
        if (is_accessible_share(share:share))
        {
          if (hotfix_is_vulnerable(file:"ppcore.dll", version:fixed_version, min_version:"12.0.0.0", path:path, bulletin:bulletin, kb:kb))
          {
            file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\ppcore.dll");
            kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
            version = get_kb_item(kb_name);

            info =
              '\n  Product           : PowerPoint 2007' +
              '\n  Path              : ' + path + '\\ppcore.dll' +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : ' + fixed_version + '\n';
            hotfix_check_fversion_end();
          }
        }
      }
    }
  }

  if (info)
  {
    hcf_report = '';
    hotfix_add_report(old_report + info, bulletin:bulletin, kb:kb);
    vuln = TRUE;
  }
}

# Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats
installs = get_kb_list("SMB/Office/PowerPointCnv/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/PowerPointCnv/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = 'n/a';
    info = "";

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    if (path != 'n/a')
    {
      path = ereg_replace(pattern:"^([A-Za-z]:.*)\\Ppcnvcom.exe", string:path, replace:"\1");

      #  PowerPoint 2007 converter.
      if (ver[0] == 12 && path)
      {
        kb = "2596843";
        fixed_version = "12.0.6654.5000";

        share = hotfix_path2share(path:path);
        if (!is_accessible_share(share:share)) exit(1, "Can't connect to "+share+" share.");

        old_report = hotfix_get_report();
        if (hotfix_is_vulnerable(file:"ppcnv.dll", version:fixed_version, min_version:"12.0.0.0", path:path, bulletin:bulletin, kb:kb))
        {
          file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\ppcnv.dll");
          kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
          version = get_kb_item(kb_name);

          vuln = TRUE;
          info =
            '\n  Product           : Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats' +
            '\n  Path              : ' + path + '\\ppcnv.dll' +
            '\n  Installed version : ' + version +
            '\n  Fixed version     : ' + fixed_version + '\n';
          hcf_report = '';
          hotfix_add_report(old_report+info, bulletin:bulletin, kb:kb);
          break;
        }
      }
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
    if (isnull(path)) path = 'n/a';

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # PowerPoint Viewer 2007.
    #
    # nb: SP3 has a file version of "12.0.6600.1000" but is not affected per
    #     MS11-094. The previous release for SP2 seems to have been for MS11-022,
    #     which brought the version to 12.0.6550.5000.
    if (ver[0] == 12 && ver[1] == 0 && ver[2] < 6600)
    {
      kb = "2596912";
      info =
        '\n  Product           : PowerPoint Viewer 2007\n' +
        '  File              : ' + path + '\n' +
        '  Installed version : ' + version + '\n' +
        '  Fixed version     : 12.0.6654.5000\n';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
      vuln = TRUE;
    }
  }
}


hotfix_check_fversion_end();

if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
