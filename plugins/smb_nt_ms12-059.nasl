#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61534);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id("CVE-2012-1888");
  script_bugtraq_id(54934);
  script_osvdb_id(84606);
  script_xref(name:"MSFT", value:"MS12-059");

  script_name(english:"MS12-059: Buffer Overflow in Microsoft Visio and Visio Viewer Could Allow Remote Code Execution (2733918)");
  script_summary(english:"Checks version of Visio.exe");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote Windows host through Visio
or Visio Viewer.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Visio or Visio Viewer
that is affected by a buffer overflow vulnerability.

A memory handling error exists when parsing specially crafted DFX files.
A remote attacker could exploit these issues by tricking a user into
opening a specially crafted Microsoft Visio file, resulting in arbitrary
code execution.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-143/");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/523938/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-059");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Visio 2010 and Visio Viewer
2010.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio_viewer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS12-059';
kbs = make_list("2597171", "2598287", "2687508");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");

vuln = FALSE;

# Visio 2010
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
        # Note KB2597171 is replaced by KB2687508 (11 DEC 2012)
        if (hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"14.0.6122.5000", min_version:"14.0.6000.0", bulletin:bulletin, kb:"2687508"))
          vuln = TRUE;
      }
    }
  }
}

# Visio Viewer 2010
# Determine the install path for Visio Viewer 2010.
visio_viewer_path = NULL;

# Connect to remote registry.
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
visio_viewer_path = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\Office\14.0\Common\InstallRoot\Path");
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

# Visio Viewer 2010.
if (visio_viewer_path)
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:visio_viewer_path);
  if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

  if (hotfix_is_vulnerable(path:visio_viewer_path, file:"Vviewer.dll", version:"14.0.6119.5000", min_version:"14.0.6000.0", bulletin:bulletin, kb:"2598287"))
    vuln = TRUE;
}

if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
