#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62905);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/04/23 21:35:42 $");

  script_cve_id("CVE-2012-2531", "CVE-2012-2532");
  script_bugtraq_id(56439, 56440);
  script_osvdb_id(87261, 87262);
  script_xref(name:"MSFT", value:"MS12-073");
  script_xref(name:"IAVB", value:"2012-B-0111");

  script_name(english:"MS12-073: Vulnerabilities in Microsoft Internet Information Services (IIS) Could Allow Information Disclosure (2733829)");
  script_summary(english:"Checks version of ftpsrv.dll and issrtl.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The Microsoft IIS service running on the remote system contains flaws
that could lead to an unauthorized information disclosure."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The FTP service in the version of IIS 7.0 or 7.5 on the remote Windows
host is affected by multiple vulnerabilities that could result in
unauthorized information disclosure."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-073");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Vista, 2008, 7, and 2008
R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

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

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS12-073';

kbs = make_list("2716513", "2719033");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;
if (
  # FTP on Windows 7 / Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"ftpsvc.dll", version:"7.5.7600.17034", min_version:"7.5.7600.0",     dir:"\system32\inetsrv", bulletin:bulletin, kb:"2716513") ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"ftpsvc.dll", version:"7.5.7600.21224", min_version:"7.5.7600.20000", dir:"\system32\inetsrv", bulletin:bulletin, kb:"2716513") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"ftpsvc.dll", version:"7.5.7601.17855", min_version:"7.5.7601.0",     dir:"\system32\inetsrv", bulletin:bulletin, kb:"2716513") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"ftpsvc.dll", version:"7.5.7601.22009", min_version:"7.5.7601.21000", dir:"\system32\inetsrv", bulletin:bulletin, kb:"2716513") ||

  # FTP on Windows Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ftpsvc.dll", version:"7.0.6545.14980", min_version:"7.0.0.0",        dir:"\system32\inetsrv", bulletin:bulletin, kb:"2716513") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ftpsvc.dll", version:"7.5.7055.14980", min_version:"7.5.0.0",        dir:"\system32\inetsrv", bulletin:bulletin, kb:"2716513") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ftpsvc.dll", version:"7.5.7600.14980", min_version:"7.5.7600.0",     dir:"\system32\inetsrv", bulletin:bulletin, kb:"2716513")
) vuln++;

if (
  # IIS on Windows Server 2008 R2 / Windows Server 2008 R2 Core / Windows 7
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"iisrtl.dll", version:"7.5.7600.17034", min_version:"7.5.7600.0",     dir:"\system32", bulletin:bulletin, kb:"2719033") ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"iisrtl.dll", version:"7.5.7600.21224", min_version:"7.5.7600.20000", dir:"\system32", bulletin:bulletin, kb:"2719033") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"iisrtl.dll", version:"7.5.7601.17855", min_version:"7.5.7601.0",     dir:"\system32", bulletin:bulletin, kb:"2719033") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"iisrtl.dll", version:"7.5.7601.22009", min_version:"7.5.7601.21000", dir:"\system32", bulletin:bulletin, kb:"2719033")
) vuln++;

if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
