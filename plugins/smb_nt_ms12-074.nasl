#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62906);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id(
    "CVE-2012-1895",
    "CVE-2012-1896",
    "CVE-2012-2519",
    "CVE-2012-4776",
    "CVE-2012-4777"
  );
  script_bugtraq_id(56455, 56456, 56462, 56463, 56464);
  script_osvdb_id(87263, 87264, 87265, 87266, 87267);
  script_xref(name:"MSFT", value:"MS12-074");
  script_xref(name:"IAVA", value:"2012-A-0184");

  script_name(english:"MS12-074: Vulnerabilities in .NET Framework Could Allow Remote Code Execution (2745030)");
  script_summary(english:"Checks file versions");

  script_set_attribute(attribute:"synopsis", value:
"The version of the .NET Framework installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of Microsoft .NET
Framework that is affected by multiple vulnerabilities :

  - The way .NET Framework validates the permissions of
    certain objects during reflection is flawed and could
    be exploited by an attacker to gain complete control of
    an affected system. (CVE-2012-1895)

  - An information disclosure vulnerability exists in .NET
    due to the improper sanitization of output when a
    function is called from partially trusted code may allow
    an attacker to obtain confidential information.
    (CVE-2012-1896)

  - A flaw exists in the way .NET handles DLL files that can
    be exploited by an attacker to execute arbitrary code.
    (CVE-2012-2519)

  - A remote code execution vulnerability exists in the way
    the .NET Framework retrieves the default web proxy
    settings. (CVE-2012-4776)

  - A flaw exists in the way .NET validates permissions for
    objects involved with reflection could be exploited by
    an attacker to gain complete control of an affected
    system. (CVE-2012-4777)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-074");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for the .NET Framework on
Windows XP, 2003, Vista, 2008, 7, 2008 R2, 8, and 2012.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("audit.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS12-074';
kbs = make_list(
  '2698023',
  '2698032',
# '2698035', # Not checked in smb_nt_ms11-078
             # Media Center Edition 2005 Service Pack 3 and Tablet PC Edition 2005 Service Pack 3 only
  '2729449',
  '2729450',
  '2729451',
  '2729452',
  '2729453',
  '2729456', # .NET 4.5 Release Candidate
# '2729457', # We don't support OS release candidates
# '2729459', # We don't support OS release candidates
  '2729460',
  '2729462',
  '2737019',
  '2737081', # .NET 4.5 Release Candidate
# '2737082', # We don't support release candidates
  '2737083',
  '2737084'
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

if ("Windows Embedded" >< productname) exit(0, "The host is running "+productname+" and hence is not affected.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;

########## KB2698023 ###########
#  .NET Framework 1.1 SP 1     #
#  Windows XP,                 #
#  Windows Server 2003 64-bit, #
#  Vista SP2,                  #
#  Server 2008 SP2             #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", arch:"x86", sp:3, file:"System.Web.dll", version:"1.1.4322.2500", dir:"\Microsoft.NET\Framework\v1.1.4322");
missing += hotfix_is_vulnerable(os:"5.2", arch:"x64", sp:2, file:"System.Web.dll", version:"1.1.4322.2500", dir:"\Microsoft.NET\Framework\v1.1.4322");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version:"1.1.4322.2500", dir:"\Microsoft.NET\Framework\v1.1.4322");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2698023');
vuln += missing;

########## KB2698032 ###########
#  .NET Framework 1.1 SP 1     #
#  Windows Server 2003 SP2     #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"5.2", arch:"x86", sp:2, file:"mscorlib.dll", version:"1.1.4322.2500", dir:"\Microsoft.NET\Framework\v1.1.4322");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2698032');
vuln += missing;

########## KB2729449 ###########
#  .NET Framework 4.0          #
#  Windows XP SP3,             #
#  Windows XP SP2 x64,         #
#  Windows 2003 SP2,           #
#  Windows Vista SP2,          #
#  Windows 7,                  #
#  Windows Server 2008 SP2,    #
#  Windows Server 2008 R2      #
################################
missing = 0;
# Windows XP SP3
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"mscorlib.dll", version:"4.0.30319.296", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"mscorlib.dll", version:"4.0.30319.586", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows XP SP2 x64 / Server 2003 SP2
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"mscorlib.dll", version:"4.0.30319.296", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"mscorlib.dll", version:"4.0.30319.586", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows Vista SP2 / Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscorlib.dll", version:"4.0.30319.296", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscorlib.dll", version:"4.0.30319.586", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows 7 / 2008 R2
missing += hotfix_is_vulnerable(os:"6.1", file:"mscorlib.dll", version:"4.0.30319.296", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", file:"mscorlib.dll", version:"4.0.30319.586", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2729449");
vuln += missing;

########## KB2729450 ###########
#  .NET Framework 2.0 SP2      #
#  Windows XP SP3,             #
#  Windows XP SP2 x64,         #
#  Windows 2003 SP2            #
################################
missing = 0;
# Windows XP SP3
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"mscorlib.dll", version:"2.0.50727.3643", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"mscorlib.dll", version:"2.0.50727.5737", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
# Windows XP SP2 x64 / Server 2003 SP2
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"mscorlib.dll", version:"2.0.50727.3643", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"mscorlib.dll", version:"2.0.50727.5737", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2729450");
vuln += missing;

########## KB2729451 ###########
#  .NET Framework 3.5.1        #
#  Windows 7,                  #
#  Server 2008 R2              #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"mscorlib.dll", version:"2.0.50727.5737", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"mscorlib.dll", version:"2.0.50727.4984", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2729451");
vuln += missing;

########## KB2729452 ###########
#  .NET Framework 3.5.1        #
#  Windows 7 SP1,              #
#  Server 2008 R2 SP1          #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"mscorlib.dll", version:"2.0.50727.5737", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"mscorlib.dll", version:"2.0.50727.5466", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2729452");
vuln += missing;

########## KB2729453 ###########
#  .NET Framework 2.0 SP2      #
#  Windows Vista SP2,          #
#  Server 2008 SP2             #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscorlib.dll", version:"2.0.50727.5737", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscorlib.dll", version:"2.0.50727.4234", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2729453");
vuln += missing;

########## KB2729460 ###########
#  .NET Framework 4.5          #
#  Windows Vista SP2,          #
#  Server 2008 SP2,            #
#  Windows 7 SP1,              #
#  Windows 2008 R2 SP1         #
################################
missing = 0;
# Windows Vista SP2 / Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.dll", version:"4.0.30319.18014", min_version:"4.0.30319.17900", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.dll", version:"4.0.30319.19019", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows 7 SP1 / 2008 R2 SP1
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.dll", version:"4.0.30319.18014", min_version:"4.0.30319.17900", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.dll", version:"4.0.30319.19019", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2729460");
vuln += missing;

########## KB2729462 ###########
#  .NET Framework 3.5          #
#  Windows 8,                  #
#  Server 2012                 #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"mscorlib.dll", version:"2.0.50727.6400", min_version:"2.0.50727.6000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"mscorlib.dll", version:"2.0.50727.7004", min_version:"2.0.50727.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2729462");
vuln += missing;

########## KB2737019 ###########
#  .NET Framework 4.0          #
#  Windows XP SP3,             #
#  Windows XP SP2 x64,         #
#  Windows 2003 SP2,           #
#  Windows Vista SP2,          #
#  Windows 7,                  #
#  Windows Server 2008 SP2,    #
#  Windows Server 2008 R2      #
################################
missing = 0;
# Windows XP
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"PresentationCore.dll", version:"4.0.30319.298", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"PresentationCore.dll", version:"4.0.30319.588", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
# Server 2003 SP2 / Windows XP SP2 X64
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"PresentationCore.dll", version:"4.0.30319.298", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"PresentationCore.dll", version:"4.0.30319.588", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
# Windows Vista SP2 / Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"PresentationCore.dll", version:"4.0.30319.298", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"PresentationCore.dll", version:"4.0.30319.588", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
# Windows 7 / 2008 R2
missing += hotfix_is_vulnerable(os:"6.1", file:"PresentationCore.dll", version:"4.0.30319.298", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
missing += hotfix_is_vulnerable(os:"6.1", file:"PresentationCore.dll", version:"4.0.30319.588", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2737019");
vuln += missing;

########## KB2737083 ###########
#  .NET Framework 4.5          #
#  Windows Vista SP2,          #
#  Server 2008 SP2,            #
#  Windows 7 SP1,              #
#  Windows 2008 R2 SP1         #
################################
missing = 0;
# Windows Vista SP2 / Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Xaml.dll", version:"4.0.30319.18015", min_version:"4.0.30319.17900", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Xaml.dll", version:"4.0.30319.19020", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows 7 SP1 / 2008 R2 SP1
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Xaml.dll", version:"4.0.30319.18015", min_version:"4.0.30319.17900", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Xaml.dll", version:"4.0.30319.19020", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2737083");
vuln += missing;

########## KB2737084 ###########
#  .NET Framework 4.5          #
#  Windows 8,                  #
#  Server 2012                 #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"presentationframework.dll", version:"4.0.30319.18016", min_version:"4.0.30319.17900", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"presentationframework.dll", version:"4.0.30319.19023", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2737084");
vuln += missing;

########## KB2729456 ###########
#  .NET Framework 4.5 RC       #
#  Windows Vista SP2,          #
#  Server 2008 SP2,            #
#  Windows 7 SP1,              #
#  Windows 2008 R2 SP1         #
################################
missing = 0;
# Windows Vista SP2 / Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.dll", version:"4.0.30319.17671", min_version:"4.0.30319.17600", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.dll", version:"4.0.30319.17800", min_version:"4.0.30319.17700", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows 7 SP1 / 2008 R2 SP1
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.dll", version:"4.0.30319.17671", min_version:"4.0.30319.17600", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.dll", version:"4.0.30319.17800", min_version:"4.0.30319.17700", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2729456");
vuln += missing;

########## KB2729457 ###########
#  .NET Framework 4.5          #
#  Release candidates for      #
#  Windows 8,                  #
#  Server 2012                 #
################################
#missing = 0;
#missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.dll", version:"4.0.30319.17802", min_version:"4.0.30319.17700", dir:"\Microsoft.NET\Framework\v4.0.30319");
#missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.dll", version:"4.0.30319.17673", min_version:"4.0.30319.17600", dir:"\Microsoft.NET\Framework\v4.0.30319");

#if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2729457");
#vuln += missing;

########## KB2737081 ###########
#  .NET Framework 4.5 RC       #
#  Windows Vista SP2,          #
#  Server 2008 SP2,            #
#  Windows 7 SP1,              #
#  Windows 2008 R2 SP1         #
################################
missing = 0;
# Windows Vista SP2 / Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"PresentationCore.dll", version:"4.0.30319.17801", min_version:"4.0.30319.17700", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"PresentationCore.dll", version:"4.0.30319.17672", min_version:"4.0.30319.17600", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
# Windows 7 SP1 / 2008 R2 SP1
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"PresentationCore.dll", version:"4.0.30319.17801", min_version:"4.0.30319.17700", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"PresentationCore.dll", version:"4.0.30319.17672", min_version:"4.0.30319.17600", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2737081");
vuln += missing;

########## KB2737082 ###########
#  .NET Framework 3.5 on       #
#  Release Candidates for      #
#  Windows 8,                  #
#  Server 2012                 #
################################
#missing = 0;
#missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"presentationcore.dll", version:"4.0.30319.17673", min_version:"4.0.30319.17600", dir:"\Microsoft.NET\Framework\v2.0.30319\WPF");
#missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"presentationcore.dll", version:"4.0.30319.17802", min_version:"4.0.30319.17700", dir:"\Microsoft.NET\Framework\v2.0.30319\WPF");

#if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2737082");
#vuln += missing;

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
