#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65212);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/01/28 22:37:17 $");

  script_cve_id("CVE-2013-0079");
  script_bugtraq_id(58369);
  script_osvdb_id(91148);
  script_xref(name:"CERT", value:"851777");
  script_xref(name:"MSFT", value:"MS13-023");
  script_xref(name:"IAVB", value:"2013-B-0028");

  script_name(english:"MS13-023: Vulnerability in Microsoft Visio Viewer 2010 Could Allow Remote Code Execution (2801261)");
  script_summary(english:"Checks file versions");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote Windows host through
Visio or Visio Viewer.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Visio, Visio Viewer,
or Microsoft Office 2010 Filter Pack that is affected by a remote code
execution vulnerability.

A flaw exists in the way Visio handles memory when rendering Visio
files. A remote attacker could exploit this issue by tricking a user
into opening a specially crafted Microsoft Visio file, resulting in
arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS13-023");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Visio Viewer
2010 SP1, Microsoft Visio 2010 SP1, and Microsoft Office 2010 Filter
Pack SP1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_filter_pack");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio_viewer");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS13-023';
kbs = make_list("2687505", "2760762", "2553501");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Uninstall/Enumerated");

common_files_dir = hotfix_get_commonfilesdir();
if (!common_files_dir) audit(AUDIT_FN_FAIL, "hotfix_get_commonfilesdir");

ms_filter_pack_installed = FALSE;
foreach name (get_kb_list('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName'))
{
  if(name == "Microsoft Filter Pack 2.0")
    ms_filter_pack_installed = TRUE;
}

vuln = FALSE;

# Visio 2010 SP1
installs = get_kb_item("SMB/Office/Visio/*/VisioPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/Visio/' - '/VisioPath';
    if ("14.0" >< version)
    {
      path = installs[install];
      share = hotfix_path2share(path:path);

      if (is_accessible_share(share:share))
      {
        # min_version enforces SP1 only is checked
        if (hotfix_is_vulnerable(path:path, file:"Sg.dll", version:"14.0.6132.5000", min_version:"14.0.6000.0", bulletin:bulletin, kb:"2760762"))
          vuln = TRUE;
      }
    }
  }
}

# Visio Viewer 2010 SP1
# Determine the install path for Visio Viewer 2010.
visio_viewer_path = NULL;

# Connect to remote registry.
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
visio_viewer_path = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\Office\14.0\Common\InstallRoot\Path");
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

# Visio Viewer 2010 SP1
if (visio_viewer_path)
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:visio_viewer_path);
  if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

  # min_version enforces SP1 only is checked
  if (hotfix_is_vulnerable(path:visio_viewer_path, file:"Vviewer.dll", version:"14.0.6131.5002", min_version:"14.0.6000.0", bulletin:bulletin, kb:"2687505"))
    vuln = TRUE;
}

# Microsoft Filter Pack 2010 SP1
if(ms_filter_pack_installed)
{
  # nb: 32 and 64 bit Microsoft Filter Pack installers use same common files path
  # min_version enforces SP1 only is checked
  if (hotfix_is_vulnerable(path:common_files_dir + "\Microsoft Shared\Filters", file:"ONIFILTER.dll", version:"14.0.6134.5000", min_version:"14.0.6000.0", bulletin:bulletin, kb:"2553501"))
    vuln = TRUE;
}

if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
