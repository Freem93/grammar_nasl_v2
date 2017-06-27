#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49695);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/06/30 19:55:38 $");

  script_cve_id("CVE-2010-3332");
  script_bugtraq_id(43316);
  script_osvdb_id(68127);
  script_xref(name:"MSFT", value:"MS10-070");

  script_name(english:"MS10-070: Vulnerability in ASP.NET Could Allow Information Disclosure (2418042)");
  script_summary(english:"Checks version of System.web.dll / System.web.extensions.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of the .NET framework installed on the remote host has an
information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"There is an information disclosure vulnerability in ASP.NET, part of
the .NET framework.  Information can be leaked due to improper error
handling during encryption padding.

A remote attacker could exploit this to decrypt and modify an ASP.NET
application's server-encrypted data.  In .NET Framework 3.5 SP1 and
above, an attacker could exploit this to download any file within the
ASP.NET application, including web.config."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-070");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for the .NET Framework on
Windows XP, 2003, Vista, 2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-070';
kbs = make_list("2416447", "2416451", "2416468", "2416469", "2416470", "2416471", "2416472", "2416473", "2416474", "2418240", "2418241");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
ver = get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

if (ver == '6.0' && hotfix_check_server_core() == 1)
  audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

ass_dir = hotfix_get_programfilesdir() + "\Reference Assemblies\Microsoft\Framework";
vuln = 0;

# 1.1 SP1 on XP, 2k3 x64, Vista, 2k8 (KB2416447)
mising = 0;
missing += hotfix_is_vulnerable(os:"5.1", file:"System.Web.dll", version:"1.1.4322.2470", min_version:"1.1.4322.0", dir:"\Microsoft.NET\Framework\v1.1.4322");
missing += hotfix_is_vulnerable(os:"5.2", arch:"x64", file:"System.Web.dll", version:"1.1.4322.2470", min_version:"1.1.4322.0", dir:"\Microsoft.NET\Framework\v1.1.4322");
missing += hotfix_is_vulnerable(os:"6.0", file:"System.Web.dll", version:"1.1.4322.2470", min_version:"1.1.4322.0", dir:"\Microsoft.NET\Framework\v1.1.4322");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2416447');
vuln += missing;

# 1.1 SP1 on 2k3 x86 (KB2416451)
missing = 0;
missing += hotfix_is_vulnerable(os:"5.2", arch:"x86", file:"System.Web.dll", version:"1.1.4322.2470", min_version:"1.1.4322.0", dir:"\Microsoft.NET\Framework\v1.1.4322");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2416451');
vuln += missing;

# 3.5 on XP, 2k3 (KB2416468)
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", file:"System.Web.dll", version:"2.0.50727.1887", min_version:"2.0.50727.1433", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", file:"System.Web.dll", version:"2.0.50727.1887", min_version:"2.0.50727.1433", dir:"\Microsoft.NET\Framework\v2.0.50727");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2416468');
vuln += missing;

# 3.5 on XP, 2k3, Vista, 2k8 (KB2418240)
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", file:"System.Web.Extensions.dll", version:"3.5.21022.239", min_version:"3.5.21022.0", path:ass_dir + "\v3.5");
missing += hotfix_is_vulnerable(os:"5.2", file:"System.Web.Extensions.dll", version:"3.5.21022.239", min_version:"3.5.21022.0", path:ass_dir + "\v3.5");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.Extensions.dll", version:"3.5.21022.239", min_version:"3.5.21022.0", path:ass_dir + "\v3.5");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2418240');
vuln += missing;

# 3.5 SP1 and 2.0 SP2 on XP, 2k3 (KB2418241)
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", file:"System.Web.dll", version:"2.0.50727.3618", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.1", file:"System.Web.dll", version:"2.0.50727.5053", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", file:"System.Web.dll", version:"2.0.50727.3618", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", file:"System.Web.dll", version:"2.0.50727.5053", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2418241');
vuln += missing;

# 3.5 SP1 on XP, 2k3, Vista, 2k8 (KB2416473)
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", file:"System.Web.Extensions.dll", version:"3.5.30729.3644", min_version:"3.5.30729.0", path:ass_dir + "\v3.5");
missing += hotfix_is_vulnerable(os:"5.1", file:"System.Web.Extensions.dll", version:"3.5.30729.5053", min_version:"3.5.30729.5000", path:ass_dir + "\v3.5");
missing += hotfix_is_vulnerable(os:"5.2", file:"System.Web.Extensions.dll", version:"3.5.30729.3644", min_version:"3.5.30729.0", path:ass_dir + "\v3.5");
missing += hotfix_is_vulnerable(os:"5.2", file:"System.Web.Extensions.dll", version:"3.5.30729.5053", min_version:"3.5.30729.5000", path:ass_dir + "\v3.5");
missing += hotfix_is_vulnerable(os:"6.0", file:"System.Web.Extensions.dll", version:"3.5.30729.3644", min_version:"3.5.30729.0", path:ass_dir + "\v3.5");
missing += hotfix_is_vulnerable(os:"6.0", file:"System.Web.Extensions.dll", version:"3.5.30729.5053", min_version:"3.5.30729.5000", path:ass_dir + "\v3.5");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2416473');
vuln += missing;

# 2.0 SP1 and 3.5 on Vista SP1 and 2008 (KB2416469)
missing = 0;
missing += hotfix_is_vulnerable(os:"6.0", sp:1, file:"System.web.dll", version:"2.0.50727.1887", min_version:"2.0.50727.1000", dir:"\Microsoft.NET\Framework\v2.0.50727");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2416469');
vuln += missing;

# 2.0 SP2 and 3.5 SP1 on Vista SP1 and 2008 (KB2416474)
missing = 0;
missing += hotfix_is_vulnerable(os:"6.0", sp:1, file:"System.web.dll", version:"2.0.50727.3618", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.0", sp:1, file:"System.web.dll", version:"2.0.50727.5053", min_version:"2.0.50727.4400", dir:"\Microsoft.NET\Framework\v2.0.50727");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2416474');
vuln += missing;

# 2.0 SP2 and 3.5 SP1 on Vista SP2, 2k8 SP2 (KB2416470)
missing = 0;
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.web.dll", version:"2.0.50727.4209", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.web.dll", version:"2.0.50727.5053", min_version:"2.0.50727.4400", dir:"\Microsoft.NET\Framework\v2.0.50727");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2416470');
vuln += missing;

# 3.5.1 on Windows 7 and 2008 R2 (KB2416471)
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"System.web.dll", version:"2.0.50727.5053", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"System.web.dll", version:"2.0.50727.4955", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2416471');
vuln += missing;

# 4.0 on XP, 2k3, Vista, 2k8, 7, 2008 R2 (KB2416472)
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", file:"System.Web.dll", version:"4.0.30319.206", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.1", file:"System.Web.dll", version:"4.0.30319.363", min_version:"4.0.30319.300", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", file:"System.Web.dll", version:"4.0.30319.206", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", file:"System.Web.dll", version:"4.0.30319.363", min_version:"4.0.30319.300", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", file:"System.Web.dll", version:"4.0.30319.206", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", file:"System.Web.dll", version:"4.0.30319.363", min_version:"4.0.30319.300", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", file:"System.Web.dll", version:"4.0.30319.206", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", file:"System.Web.dll", version:"4.0.30319.363", min_version:"4.0.30319.300", dir:"\Microsoft.NET\Framework\v4.0.30319");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2416472');
vuln += missing;

if (vuln > 0)
{
  set_kb_item(name:"SMB/Missing/MS10-070", value:TRUE);
  hotfix_security_warning();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
