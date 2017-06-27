#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95772);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/23 20:31:20 $");

  script_cve_id("CVE-2016-7270");
  script_bugtraq_id(94741);
  script_osvdb_id(148623);
  script_xref(name:"MSFT", value:"MS16-155");
  script_xref(name:"IAVA", value:"2016-A-0349");

  script_name(english:"MS16-155: Security Update for .NET Framework (3205640)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by an information disclosure vulnerability in the
.NET Framework Data Provider for SQL Server due to improper handling
of developer-supplied keys. An unauthenticated, remote attacker can
exploit this to disclose sensitive information that should be
protected by the Always Encrypted feature. Furthermore, an attacker
who can access incorrectly encrypted data could decrypt that data by
using an easily guessable key. Misuse of the key can also result in
access to data being temporarily lost.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms16-155");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft .NET Framework 4.6.2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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
bulletin = 'MS16-155';

kbs = make_list(
  "3204801", # Server 2012 .NET 4.6.2 Security Only
  "3204802", # 8.1 / 2012 R2 .NET 4.6.2 Security Only
  "3204805", # 7 / 2008 R2 .NET 4.6.2 Security Only
  "3205377", # Server 2012 .NET 4.6.2 Monthly Rollup
  "3205378", # 8.1 / 2012 R2 .NET 4.6.2 Monthly Rollup
  "3205379", # 7 / 2008 R2 .NET 4.6.2 Monthly Rollup
  "3206632" # 10 Version 1607 / Server 2016 .NET 4.6.2
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
  local_var dotnet_452_installed, dotnet_46_installed, dotnet_461_installed, dotnet_35_installed, dotnet_462_installed;
  local_var ver, missing, count, installs, install;

  # Determine if .NET 4.6.2 is installed
  dotnet_462_installed = FALSE;

  # Make sure to add dependency for microsoft_net_framework_installed.nasl
  count = get_install_count(app_name:'Microsoft .NET Framework');
  if (count > 0)
  {
    installs = get_installs(app_name:'Microsoft .NET Framework');
    foreach install(installs[1])
    {
      ver = install["version"];
      if (ver == "4.6.2") dotnet_462_installed = TRUE;
    }
  }
  # .NET 4.6.2
  if (dotnet_462_installed)
  {
    ############# KB3206632 #############
    # .NET Framework 4.6.2              #
    #  Windows 10 Version 1607          #
    #  Server 2016                      #
    #####################################
    missing = 0;
    missing += hotfix_is_vulnerable(os:"10", sp:0, os_build:"14393", file:"system.data.dll", version:"4.6.1636.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3206632");
    vuln += missing;

    ########### KB3204801 / KB3205377 ####
    # .NET Framework 4.6.2 Security Only #
    # Windows Server 2012                #
    # KB3204801 Security Only            #
    # KB3205377 Monthly Rollup           #
    ######################################
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.data.dll", version:"4.6.1636.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3204801");
    vuln += missing;

    ############ KB3204802 / KB3205378 ###
    # .NET Framework 4.6.2 Security Only #
    # Windows 8.1                        #
    # Windows Server 2012 R2             #
    # KB3204802 Security Only            #
    # KB3205378 Monthly Rollup           #
    ######################################
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.data.dll", version:"4.6.1636.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3204802");
    vuln += missing;

    ########### KB3204805 / KB3205379 ####
    # .NET Framework 4.6.2 Security Only #
    # Windows 7 SP1                      #
    # Windows Server 2008 R2 SP1         #
    # KB3204805 Security Only            #
    # KB3205379 Monthly Rollup           #
    ######################################
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.data.dll", version:"4.6.1636.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3204805");
    vuln += missing;
  }
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
