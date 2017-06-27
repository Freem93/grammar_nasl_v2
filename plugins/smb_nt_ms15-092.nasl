#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85331);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/08/16 04:44:42 $");

  script_cve_id(
    "CVE-2015-2479",
    "CVE-2015-2480",
    "CVE-2015-2481"
  );
  script_bugtraq_id(
    76268,
    76269,
    76270
  );
  script_osvdb_id(
    126001,
    126002,
    126003
  );
  script_xref(name:"MSFT", value:"MS15-092");
  script_xref(name:"IAVA", value:"2015-A-0195");

  script_name(english:"MS15-092: Vulnerabilities in .NET Framework Could Allow Elevation of Privilege (3086251)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The version of the .NET Framework installed on the remote host is
affected by multiple elevation of privilege vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft .NET Framework installed on the remote host
is affected by multiple elevation of privilege vulnerabilities due to
the RyuJIT compiler not properly optimizing certain parameters,
resulting in a code generation error. A remote attacker, by convincing
a user to run a malicious .NET application, can exploit these
vulnerabilities to gain elevated privileges and take control of the
affected system.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-092");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for .NET Framework 4.6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/08/11");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/11");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "microsoft_net_framework_installed.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS15-092';
kbs = make_list('3081436','3083184','3083185','3083186');


if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# Determine if .NET 4.6 is installed
dotnet_46 = FALSE;

get_install_count(app_name:'Microsoft .NET Framework', exit_if_zero:TRUE);
installs = get_installs(app_name:'Microsoft .NET Framework');

foreach install(installs[1])
{
  ver = install["version"];
  if (ver == "4.6" || ver == "4.6 Preview")
    dotnet_46 = TRUE;
}

if(! dotnet_46)
  audit(AUDIT_HOST_NOT, "affected");

vuln = 0;

############ KB3083184 ##############
#  .NET Framework 4.6               #
#  Windows 8,                       #
#  Server 2012                      #
#####################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.2", arch:"x86", sp:0, file:"Mscorlib.dll", version:"4.6.96.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.2", arch:"x64", sp:0, file:"Mscorlib.dll", version:"4.6.96.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework64\v4.0.30319");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3083184");
vuln += missing;

############ KB3083185 ##############
#  .NET Framework 4.6               #
#  Windows 8.1,                     #
#  Server 2012 R2                   #
#####################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.3", arch:"x86", sp:0, file:"Mscordacwks.dll", version:"4.6.96.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.3", arch:"x64", sp:0, file:"Mscordacwks.dll", version:"4.6.96.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework64\v4.0.30319");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3083185");
vuln += missing;

############ KB3083186 ##############
#  .NET Framework 4.6               #
#  Windows 7 SP 1                   #
#  Server 2008 R2 SP 1              #
#  Windows Vista SP 2               #
#  Server 2008 SP 2                 #
#####################################
missing = 0;
# Windows Vista SP2 / Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", arch:"x86", sp:2, file:"Mscorlib.dll", version:"4.6.100.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", arch:"x64", sp:2, file:"Mscorlib.dll", version:"4.6.100.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework64\v4.0.30319");
# Windows 7 SP1 / 2008 R2 SP1
missing += hotfix_is_vulnerable(os:"6.1", arch:"x86", sp:1, file:"Mscorlib.dll", version:"4.6.100.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", arch:"x64", sp:1, file:"Mscorlib.dll", version:"4.6.100.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework64\v4.0.30319");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3083186");
vuln += missing;

############ KB3081436 ##############
#  .NET Framework 4.6               #
#  Windows 10                       #
#####################################
missing = 0;
missing += hotfix_is_vulnerable(os:"10", arch:"x86", sp:0, file:"Mscorlib.dll", version:"4.6.96.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"10", arch:"x64", sp:0, file:"Mscorlib.dll", version:"4.6.96.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework64\v4.0.30319");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3081436");
vuln += missing;

if(vuln > 0)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, "affected");
}
