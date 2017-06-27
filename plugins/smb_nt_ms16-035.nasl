#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89757);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/07/18 20:50:58 $");

  script_cve_id("CVE-2016-0132");
  script_bugtraq_id(84075);
  script_osvdb_id(135549);
  script_xref(name:"MSFT", value:"MS16-035");
  script_xref(name:"IAVA", value:"2016-A-0068");

  script_name(english:"MS16-035: Security Update for .NET Framework to Address Security Feature Bypass (3141780)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a security feature bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by a security feature bypass vulnerability in the
.NET Framework due to improper validation of certain elements in a
signed XML document. An attacker can exploit this vulnerability to
modify the contents of an XML file without invalidating the signature
associated with the file.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms16-035");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for .NET Framework 2.0 SP2,
3.0 SP2, 3.5, 3.5.1, 4, 4.5.1, 4.5.2, 4.6, and 4.6.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/08");

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
bulletin = 'MS16-035';

kbs = make_list(
  "3135998",
  "3135997",
  "3136000",
  "3135994",
  "3135995",
  "3135996",
  "3135983",
  "3135985",
  "3135991",
  "3135989",
  "3135984",
  "3135988",
  "3135987",
  "3135982"
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

  ########## KB3135982 #############
  # .NET Framework 2.0 SP2         #
  # Windows Vista SP2              #
  # Windows Server 2008 SP2        #
  ##################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.security.dll", version:"2.0.50727.4262", min_version:"2.0.50727.0",    dir:"\Microsoft.NET\Framework\v2.0.50727");
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.security.dll", version:"2.0.50727.8683", min_version:"2.0.50727.6500", dir:"\Microsoft.NET\Framework\v2.0.50727");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3135982");
  vuln += missing;

  ########### KB3135983 #############
  # .NET Framework 3.5.1            #
  # Windows 7 SP1                   #
  # Windows Server 2008 R2 SP1      #
  ###################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.security.dll", version:"2.0.50727.5496", min_version:"2.0.50727.0",    dir:"\Microsoft.NET\Framework\v2.0.50727");
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.security.dll", version:"2.0.50727.8683", min_version:"2.0.50727.6500", dir:"\Microsoft.NET\Framework\v2.0.50727");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3135983");
  vuln += missing;

  ########### KB3135991 ###########
  # .NET Framework 3.5            #
  # Windows 8.1                   #
  # Windows Server 2012 R2        #
  #################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.printing.dll", version:"3.0.6920.8010", min_version:"3.0.6920.0",    dir:"\Microsoft.NET\Framework\v2.0.50727");
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.printing.dll", version:"3.0.6920.8702", min_version:"3.0.6920.8500", dir:"\Microsoft.NET\Framework\v2.0.50727");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3135991");
  vuln += missing;

  ########### KB3135989 ###########
  # .NET Framework 3.5            #
  # Windows Server 2012           #
  #################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.printing.dll", version:"3.0.6920.6423", min_version:"3.0.6920.0",    dir:"\Microsoft.NET\Framework\v2.0.50727");
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.printing.dll", version:"3.0.6920.8699", min_version:"3.0.6920.8500", dir:"\Microsoft.NET\Framework\v2.0.50727");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3135989");
  vuln += missing;

  ############ KB3135984 ############
  # .NET Framework 3.5              #
  # Windows Server 2012             #
  ###################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.security.dll", version:"2.0.50727.6432", min_version:"2.0.50727.0",    dir:"\Microsoft.NET\Framework\v2.0.50727");
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.security.dll", version:"2.0.50727.8685", min_version:"2.0.50727.8300", dir:"\Microsoft.NET\Framework\v2.0.50727");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3135984");
  vuln += missing;

  ############ KB3135985 ############
  # .NET Framework 3.5              #
  # Windows 8.1                     #
  # Windows Server 2012 R2          #
  ###################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.security.dll", version:"2.0.50727.8020", min_version:"2.0.50727.0",    dir:"\Microsoft.NET\Framework\v2.0.50727");
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.security.dll", version:"2.0.50727.8685", min_version:"2.0.50727.8300", dir:"\Microsoft.NET\Framework\v2.0.50727");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3135985");
  vuln += missing;

  ############ KB3135987 ############
  # .NET Framework 3.0              #
  # Windows Vista                   #
  # Windows 7                       #
  # Windows 2008                    #
  # Windows 2008 R2                 #
  ###################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpfgfx_v0300.dll", version:"3.0.6920.4231", min_version:"3.0.6920.0", dir:"\Microsoft.NET\Framework\v3.0\WPF");
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpfgfx_v0300.dll", version:"3.0.6920.8702", min_version:"3.0.6920.7000", dir:"\Microsoft.NET\Framework\v3.0\WPF");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3135987");
  vuln += missing;

  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.1", sp:2, file:"wpfgfx_v0300.dll", version:"3.0.6920.5471", min_version:"3.0.6920.0", dir:"\Microsoft.NET\Framework\v3.0\WPF");
  missing += hotfix_is_vulnerable(os:"6.1", sp:2, file:"wpfgfx_v0300.dll", version:"3.0.6920.8699", min_version:"3.0.6920.7000", dir:"\Microsoft.NET\Framework\v3.0\WPF");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3135988");
  vuln += missing;

  ############ KB3135994 ############
  # .NET Framework 4.5.2            #
  # Windows 8.1                     #
  # Windows Server 2012 R2          #
  ###################################
  if (dotnet_452_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.security.dll", version:"4.0.30319.34292", min_version:"4.0.30319.0",     dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.security.dll", version:"4.0.30319.36346", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3135994");
    vuln += missing;
  }

  ########### KB3135995 ###########
  # .NET Framework 4.5.2          #
  # Windows Server 2012           #
  #################################
  if (dotnet_452_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.security.dll", version:"4.0.30319.34292", min_version:"4.0.30319.0",     dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.security.dll", version:"4.0.30319.36346", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3135995");
    vuln += missing;
  }


  ########## KB3135996 #############
  # .NET Framework 4.5.2           #
  # Windows Vista SP2              #
  # Windows Server 2008 SP2        #
  # Windows 7 SP1                  #
  # Windows Server 2008 R2 SP1     #
  ##################################
  if (dotnet_452_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.security.dll", version:"4.0.30319.34291", min_version:"4.0.30319.0",     dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.security.dll", version:"4.0.30319.36346", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.security.dll", version:"4.0.30319.34291", min_version:"4.0.30319.0",     dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.security.dll", version:"4.0.30319.36346", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3135996");
    vuln += missing;
  }

  ########### KB3135997 ###########
  # .NET Framework 4.6 / 4.6.1    #
  # Windows Server 2012           #
  #################################
  if (dotnet_46_installed || dotnet_461_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.security.dll", version:"4.6.1073.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3135997");
    vuln += missing;
  }

  ############ KB3135998 ############
  # .NET Framework 4.6 / 4.6.1      #
  # Windows 8.1                     #
  # Windows Server 2012 R2          #
  ###################################
  if (dotnet_46_installed || dotnet_461_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.security.dll", version:"4.6.1073.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3135998");
    vuln += missing;
  }

  ########## KB3136000 #############
  # .NET Framework 4.6             #
  # Windows Vista SP2              #
  # Windows Server 2008 SP2        #
  # Windows 7 SP1                  #
  #  Windows Server 2008 R2 SP1    #
  ##################################
  if (dotnet_46_installed || dotnet_461_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.security.dll", version:"4.6.1071.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.security.dll", version:"4.6.1071.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3136000");
    vuln += missing;
  }

  ############# KB3140745 #############
  #  .NET Framework 3.5               #
  #  Windows 10                       #
  #####################################
  if (dotnet_35_installed)
  {
    #  3.5 is optional addon in 10
    missing = 0;
    missing += hotfix_is_vulnerable(os:"10", sp:0, file:"system.security.dll", version:"2.0.50727.8685", min_version:"2.0.50727.6500", dir:"\Microsoft.NET\Framework\v2.0.50727");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3140745");
    vuln += missing;
  }

  ############# KB3140745 #############
  #  .NET Framework                   #
  #  Windows 10                       #
  #####################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"10", sp:0, file:"system.security.dll", version:"4.6.1073.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3140745");
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
