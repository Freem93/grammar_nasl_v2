#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51904);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2015/04/23 21:35:40 $");

  script_cve_id("CVE-2010-3972");
  script_bugtraq_id(45542);
  script_osvdb_id(70167);
  script_xref(name:"EDB-ID", value:"15803");
  script_xref(name:"MSFT", value:"MS11-004");

  script_name(english:"MS11-004: Vulnerability in Internet Information Services (IIS) FTP Service Could Allow Remote Code Execution (2489256)");
  script_summary(english:"Checks version of ftpsvc.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The FTP service running on the remote host has a memory corruption
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The IIS FTP service running on the remote host has a heap-based buffer
overflow vulnerability.  The 'TELNET_STREAM_CONTEXT::OnSendData'
function fails to properly sanitize user input, resulting in a buffer
overflow.

An unauthenticated, remote attacker can exploit this to execute
arbitrary code."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-004");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows Vista, 2008, 2008
R2, and 7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_enum_services.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS11-004';
kb = '2489256';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

get_kb_item_or_exit('SMB/svc/ftpsvc');  # cheap way to see if FTP 7.0/7.5 is installed

if (hotfix_check_sp_range(vista:'1,2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

#    Remote version : 7.5.7600.14978
#    Should be : 7.5.7600.16748

if (
  # FTP 7.5 on IIS 7.5
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"ftpsvc.dll", version:"7.5.7601.21649", min_version:"7.5.7601.21000", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"ftpsvc.dll", version:"7.5.7601.17550", min_version:"7.5.7601.0", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"ftpsvc.dll", version:"7.5.7600.20888", min_version:"7.5.7600.20000", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"ftpsvc.dll", version:"7.5.7600.16748", min_version:"7.5.0.0", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb) ||

  # FTP 7.5 on IIS 7.0 (LDR not listed in KB article)
  hotfix_is_vulnerable(os:"6.0", file:"ftpsvc.dll", version:"7.5.7600.14978", min_version:"7.5.0.0", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb) ||

  # FTP 7.0 on IIS 7.0 (LDR not listed in KB article)
  hotfix_is_vulnerable(os:"6.0", file:"ftpsvc.dll", version:"7.0.6545.14979", min_version:"7.0.0.0", dir:"\system32\inetsrv", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
