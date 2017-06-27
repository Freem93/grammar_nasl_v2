#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77164);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2014-4062");
  script_bugtraq_id(69145);
  script_osvdb_id(109937);
  script_xref(name:"MSFT", value:"MS14-046");
  script_xref(name:"IAVA", value:"2014-A-0128");

  script_name(english:"MS14-046: Vulnerability in .NET Framework Could Allow Security Feature Bypass (2984625)");
  script_summary(english:"Checks the version of the .NET files.");

  script_set_attribute(attribute:"synopsis", value:
"The version of the .NET Framework installed on the remote host is
affected by a security feature bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of the Microsoft .NET Framework
that is affected by a vulnerability that could allow an attacker to
bypass the Address Space Layout Randomization (ASLR) security feature.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS14-046");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for .NET Framework 2.0 SP2,
3.0 SP2, 3.5, and 3.5.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");
include("smb_reg_query.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS14-046';
kbs = make_list(
  "2937608",
  "2943344",
  "2966825",
  "2966827",
  "2966826",
  "2966828",
  "2937610",
  "2943357"
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Windows 2008 Server Server Core is not affected.
if ('6.0' >< get_kb_item("SMB/WindowsVersion") && hotfix_check_server_core()) audit(AUDIT_WIN_SERVER_CORE);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

# Windows RT and Windows RT 8.1 not affected
if ("Windows RT" >< productname)
  exit(0, "The host is running "+productname+" and is, therefore, not affected.");

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

assembly_dir_30 = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\.NETFramework\AssemblyFolders\v3.0\All Assemblies In");

assembly_dir_35 = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\.NETFramework\AssemblyFolders\v3.5\All Assemblies In");
RegCloseKey(handle:hklm);

close_registry();

vuln = 0;

########## KB2937608 ###########
# .NET Framework 2.0 SP2       #
# Windows Vista SP2            #
# Windows Server 2008 SP2      #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscorlib.dll", version:"2.0.50727.7067", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscorlib.dll", version:"2.0.50727.4252", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2937608");
vuln += missing;

########## KB2943344 ###########
# .NET Framework 3.0 SP2       #
# Windows Vista SP2            #
# Windows Server 2008 SP2      #
################################
if (!isnull(assembly_dir_30))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"icardres.dll", version:"3.0.4506.4223", min_version:"3.0.4506.4000", dir:"\system32");
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"icardres.dll", version:"3.0.4506.7082", min_version:"3.0.4506.5000", dir:"\system32");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2943344");
  vuln += missing;
}

########## KB2943357 ###########
# .NET Framework 3.5.1         #
# Windows 7 SP1                #
# Windows Server 2008 R2 SP1   #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.runtime.serialization.dll", version:"3.0.4506.5461", min_version:"3.0.4506.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.runtime.serialization.dll", version:"3.0.4506.7082", min_version:"3.0.4506.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2943357");
vuln += missing;

########## KB2937610 ###########
# .NET Framework 3.5.1         #
# Windows 7 SP1                #
# Windows Server 2008 R2 SP1   #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.xml.dll", version:"2.0.50727.5483", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.xml.dll", version:"2.0.50727.7057", min_version:"2.0.50727.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2937610");
vuln += missing;

########## KB2966827 ###########
# .NET Framework 3.5           #
# Windows 8                    #
# Windows Server 2012          #
################################
if (!isnull(assembly_dir_35))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.runtime.serialization.dll", version:"3.0.4506.6416", min_version:"3.0.4506.6000", path:assembly_dir_35);
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.runtime.serialization.dll", version:"3.0.4506.7082", min_version:"3.0.4506.7000", path:assembly_dir_35);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2966827");
  vuln += missing;
}

########## KB2966825 ###########
# .NET Framework 3.5           #
# Windows 8                    #
# Windows Server 2012          #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"mscorlib.dll", version:"2.0.50727.6419", min_version:"2.0.50727.6000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"mscorlib.dll", version:"2.0.50727.7057", min_version:"2.0.50727.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2966825");
vuln += missing;

########## KB2966828 ###########
# .NET Framework 3.5           #
# Windows 8.1                  #
# Windows Server 2012 R2       #
################################
if (!isnull(assembly_dir_35))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.runtime.serialization.dll", version:"3.0.4506.8603", min_version:"3.0.4506.8600", path:assembly_dir_35);
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.runtime.serialization.dll", version:"3.0.4506.8003", min_version:"3.0.4506.0", path:assembly_dir_35);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2966828");
  vuln += missing;
}

########## KB2966826 ###########
# .NET Framework 3.5           #
# Windows 8.1                  #
# Windows Server 2012 R2       #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"mscorlib.dll", version:"2.0.50727.8612", min_version:"2.0.50727.8600", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"mscorlib.dll", version:"2.0.50727.8007", min_version:"2.0.50727.0", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2966826");
vuln += missing;

if(vuln > 0)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, "affected");
}
