#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90435);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/07/18 20:50:59 $");

  script_cve_id("CVE-2016-0148");
  script_bugtraq_id(85937);
  script_osvdb_id(136967);
  script_xref(name:"MSFT", value:"MS16-041");
  script_xref(name:"IAVB", value:"2016-B-0069");

  script_name(english:"MS16-041: Security Update for .NET Framework (3148789)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a software framework installed that is
affected by a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft .NET Framework installed on the remote host
is affected by a code execution vulnerability due to improper
validation of input before loading libraries. A local attacker can
exploit this, via a malicious application, to execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-041");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for .NET Framework 4.6 and
4.6.1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/04/12");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/12");

  script_set_attribute(attribute:"plugin_type",value:"local");
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
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-041';
kb = '3143693';
kbs = make_list(kb);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# Determine if .NET 4.6.1 / 4.6 is installed
dotnet_46 = FALSE;
dotnet_461 = FALSE;

get_install_count(app_name:'Microsoft .NET Framework', exit_if_zero:TRUE);
installs = get_installs(app_name:'Microsoft .NET Framework');

foreach install(installs[1])
{
  ver = install["version"];
  if (ver == "4.6.1") dotnet_461 = TRUE;
  if (ver == "4.6") dotnet_46 = TRUE;
}

if(!dotnet_46 && !dotnet_461)
  audit(AUDIT_HOST_NOT, "affected");

vuln = 0;

############ KB3143693 ##############
#  .NET Framework 4.6 / 4.6.1       #
#  Windows Vista SP2,               #
#  Server 2008 SP2,                 #
#  Windows 7 SP1                    #
#  Server 2008 R2 SP1               #
#####################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x86", file:"Mscorlib.dll", version:"4.6.1076.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

missing += hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x64", file:"Mscorlib.dll", version:"4.6.1076.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework64\v4.0.30319");

missing += hotfix_is_vulnerable(os:"6.1", arch:"x86", sp:1, file:"Mscorlib.dll", version:"4.6.1076.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

missing += hotfix_is_vulnerable(os:"6.1", arch:"x64", sp:1, file:"Mscorlib.dll", version:"4.6.1076.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework64\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:kb);
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
