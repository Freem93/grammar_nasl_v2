#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(53859);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/07/11 14:12:52 $");

  script_cve_id("CVE-2011-1269", "CVE-2011-1270");
  script_bugtraq_id(47699, 47700);
  script_osvdb_id(72235, 72236);
  script_xref(name:"MSFT", value:"MS11-036");
  script_xref(name:"IAVA", value:"2011-A-0063");

  script_name(english:"MS11-036: Vulnerabilities in Microsoft PowerPoint Could Allow Remote Code Execution (2545814)");
  script_summary(english:"Checks Office version");

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
affected by multiple vulnerabilities that could lead to arbitrary
code execution :

  - A memory corruption vulnerability exists due to the
    application's failure to properly handle memory during
    function calls while parsing a specially crafted
    PowerPoint file. (CVE-2011-1269)

  - A buffer overflow can be triggered when the application
    encounters a memory handling error while parsing a
    specially crafted PowerPoint file. (CVE-2011-1270)

If a remote attacker can trick a user into opening a malicious
PowerPoint file using the affected install, either of these
vulnerabilities could be leveraged to execute arbitrary code subject
to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-036");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for PowerPoint 2002, 2003,
and 2007 as well as Office Compatibility Pack."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
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

bulletin = 'MS11-036';
kbs = make_list("2535802", "2535812", "2535818", "2540162");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);



vuln = FALSE;


# Check PowerPoint versions.
installs = get_kb_list("SMB/Office/PowerPoint/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    info = NULL;
    version = install - 'SMB/Office/PowerPoint/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = "n/a";

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    old_report = hotfix_get_report();
    # PowerPoint 2007.
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (ver[0] == 12 && (!isnull(office_sp) && office_sp == 2))
    {
      kb = "2535818";
      fixed_version = "12.0.6557.5001";

      if (path != "n/a")
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
    # PowerPoint 2003.
    else if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8335)
    {
      office_sp = get_kb_item("SMB/Office/2003/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        kb = "2535812";
        info =
          '\n  Product           : PowerPoint 2003\n' +
          '  File              : ' + path + '\n' +
          '  Installed version : ' + version + '\n' +
          '  Fixed version     : 11.0.8335.0\n';
      }
    }
    # PowerPoint 2002.
    else if (ver[0] == 10 && ver[1] == 0 && ver[2] < 6872)
    {
      office_sp = get_kb_item("SMB/Office/XP/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        kb = "2535802";
        info =
          '\n  Product           : PowerPoint 2002\n' +
          '  File              : ' + path + '\n' +
          '  Installed version : ' + version + '\n' +
          '  Fixed version     : 10.0.6872.0\n';
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

# PowerPoint Converter.
installs = get_kb_list("SMB/Office/PowerPointCnv/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    info = NULL;
    version = install - 'SMB/Office/PowerPointCnv/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = 'n/a';

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    if (path != 'n/a')
    {
      path = ereg_replace(pattern:"^([A-Za-z]:.*)\\Ppcnvcom.exe", string:path, replace:"\1");

      #  PowerPoint 2007 converter.
      if (ver[0] == 12 && path)
      {
        kb = "2540162";
        fixed_version = "12.0.6557.5001";

         share = hotfix_path2share(path:path);
        if (is_accessible_share(share:share))
        {
          old_report = hotfix_get_report();
          if (hotfix_is_vulnerable(file:"ppcnv.dll", version:fixed_version, min_version:"12.0.0.0", path:path, bulletin:bulletin, kb:kb))
          {
            file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\ppcnv.dll");
            kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
            version = get_kb_item(kb_name);

            vuln = TRUE;
            info =
              '\n  Product           : PowerPoint 2007 Converter' +
              '\n  Path              : ' + path + '\\ppcnv.dll' +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : ' + fixed_version + '\n';
            hcf_report = '';
            hotfix_add_report(old_report+info, bulletin:bulletin, kb:kb);
          }
        }
      }
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
