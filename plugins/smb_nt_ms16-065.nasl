#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91014);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/07/13 20:59:28 $");

  script_cve_id("CVE-2016-0149");
  script_bugtraq_id(90026);
  script_osvdb_id(138340);
  script_xref(name:"MSFT", value:"MS16-065");
  script_xref(name:"IAVB", value:"2016-B-0087");

  script_name(english:"MS16-065: Security Update for .NET Framework (3156757)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by an information disclosure vulnerability in the
.NET Framework encryption component. A man-in-the-middle attacker can
exploit this vulnerability by injecting unencrypted data into the
secure channel between a targeted client and a legitimate server,
allowing the attacker to decrypt encrypted SSL/TLS traffic.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms16-065");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft .NET Framework
2.0 SP2, 3.5, 3.5.1, 4.5.2, 4.6, and 4.6.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "microsoft_net_framework_installed.nasl");
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
include("install_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

global_var bulletin, vuln, arch;

arch = get_kb_item_or_exit('SMB/ARCH');
vuln = 0;
bulletin = 'MS16-065';

kbs = make_list(
  "3142023",
  "3142024",
  "3142025",
  "3142026",
  "3142030",
  "3142032",
  "3142033",
  "3142035",
  "3142036",
  "3142037",
  "3156387",
  "3156421"
);


if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
winver = get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);
if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "Windows 8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# dotnet checks
function perform_dotnet_checks()
{
  local_var dotnet_452_installed, dotnet_46_installed, dotnet_461_installed, dotnet_35_installed;
  local_var ver, missing, count, installs, install;

  # Determine if .NET 4.5.2 or 4.6 is installed
  dotnet_452_installed = FALSE;
  dotnet_46_installed  = FALSE;
  dotnet_461_installed = FALSE;
  dotnet_35_installed  = FALSE;

  # Make sure to add dependency for microsoft_net_framework_installed.nasl
  count = get_install_count(app_name:'Microsoft .NET Framework');
  if (count > 0)
  {
    installs = get_installs(app_name:'Microsoft .NET Framework');
    foreach install(installs[1])
    {
      ver = install["version"];
      if (ver == "4.6.1") dotnet_461_installed = TRUE;
      if (ver == "4.6") dotnet_46_installed = TRUE;
      if (ver == "4.5.2") dotnet_452_installed = TRUE;
      if (ver == "3.5") dotnet_35_installed = TRUE;
    }
  }

  ########## KB3142023 #############
  # .NET Framework 2.0 SP2         #
  # Windows Vista SP2              #
  # Windows Server 2008 SP2        #
  ##################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.dll", version:"2.0.50727.4264", min_version:"2.0.50727.0",    dir:"\Microsoft.NET\Framework\v2.0.50727");
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.dll", version:"2.0.50727.8686", min_version:"2.0.50727.6500", dir:"\Microsoft.NET\Framework\v2.0.50727");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3142023");
  vuln += missing;

  if (dotnet_35_installed)
  {
    ########### KB3142024 #############
    # .NET Framework 3.5.1            #
    # Windows 7 SP1                   #
    # Windows Server 2008 R2 SP1      #
    ###################################
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.dll", version:"2.0.50727.8686", min_version:"2.0.50727.0", dir:"\Microsoft.NET\Framework\v2.0.50727");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3142024");
    vuln += missing;

    ########### KB3142026 ###########
    # .NET Framework 3.5            #
    # Windows 8.1                   #
    # Windows Server 2012 R2        #
    #################################
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.dll", version:"2.0.50727.8686", min_version:"2.0.50727.0", dir:"\Microsoft.NET\Framework\v2.0.50727");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3142026");
    vuln += missing;

    ########### KB3142025 ###########
    # .NET Framework 3.5            #
    # Windows Server 2012           #
    #################################
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.dll", version:"2.0.50727.8686", min_version:"2.0.50727.0", dir:"\Microsoft.NET\Framework\v2.0.50727");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3142025");
    vuln += missing;
  }

  ############ KB3142030 ############
  # .NET Framework 4.5.2            #
  # Windows 8.1                     #
  # Windows Server 2012 R2          #
  ###################################
  if (dotnet_452_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.dll", version:"4.0.30319.36350", min_version:"4.0.30319.34000", dir:"\Microsoft.NET\Framework\v4.0.30319");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3142030");
    vuln += missing;
  }

  ########### KB3142032 ###########
  # .NET Framework 4.5.2          #
  # Windows Server 2012           #
  #################################
  if (dotnet_452_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.dll", version:"4.0.30319.36350", min_version:"4.0.30319.34000", dir:"\Microsoft.NET\Framework\v4.0.30319");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3142032");
    vuln += missing;
  }


  ########## KB3142033 #############
  # .NET Framework 4.5.2           #
  # Windows Vista SP2              #
  # Windows Server 2008 SP2        #
  # Windows 7 SP1                  #
  # Windows Server 2008 R2 SP1     #
  ##################################
  if (dotnet_452_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.dll", version:"4.0.30319.34294", min_version:"4.0.30319.34000",     dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.dll", version:"4.0.30319.36351", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.dll", version:"4.0.30319.34294", min_version:"4.0.30319.34000",     dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.dll", version:"4.0.30319.36351", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3142033");
    vuln += missing;
  }

  ########### KB3142035 ###########
  # .NET Framework 4.6 / 4.6.1    #
  # Windows Server 2012           #
  #################################
  if (dotnet_46_installed || dotnet_461_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.dll", version:"4.6.1075.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3142035");
    vuln += missing;
  }

  ############ KB3142036 ############
  # .NET Framework 4.6 / 4.6.1      #
  # Windows 8.1                     #
  # Windows Server 2012 R2          #
  ###################################
  if (dotnet_46_installed || dotnet_461_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.dll", version:"4.6.1075.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3142036");
    vuln += missing;
  }

  ########## KB3142037 #############
  # .NET Framework 4.6             #
  # Windows Vista SP2              #
  # Windows Server 2008 SP2        #
  # Windows 7 SP1                  #
  #  Windows Server 2008 R2 SP1    #
  ##################################
  if (dotnet_46_installed || dotnet_461_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.dll", version:"4.6.1075.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.dll", version:"4.6.1075.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3142037");
    vuln += missing;
  }

  ############# KB3156387 #############
  #  .NET Framework                   #
  #  Windows 10                       #
  #####################################
  if (dotnet_35_installed)
  {
    #  3.5 is optional addon in 10
    missing = 0;
    missing += hotfix_is_vulnerable(os:"10", sp:0, file:"system.dll", version:"2.0.50727.8686", min_version:"2.0.50727.6500", dir:"\Microsoft.NET\Framework\v2.0.50727");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3156387");
    vuln += missing;
  }
  missing = 0;
  missing += hotfix_is_vulnerable(os:"10", sp:0, file:"system.dll", version:"4.6.1075.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3156387");
  vuln += missing;
}

perform_dotnet_checks();

if(vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
