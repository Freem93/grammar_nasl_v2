#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62903);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/04/23 21:35:42 $");

  script_cve_id("CVE-2012-1538", "CVE-2012-1539", "CVE-2012-4775");
  script_bugtraq_id(56420, 56421, 56422);
  script_osvdb_id(87256, 87257, 87258);
  script_xref(name:"MSFT", value:"MS12-071");

  script_name(english:"MS12-071: Cumulative Security Update for Internet Explorer (2761451)");
  script_summary(english:"Checks version of Mshtml.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a web browser that is affected by code execution
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is missing Internet Explorer (IE) Security Update
2761451.

The installed version of IE is affected by vulnerabilities that could
allow an attacker to execute arbitrary code on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-071");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Vista, 2008, 7, and 2008
R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
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
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS12-071';
kb = '2761451';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);


if (
  # Windows 7 / 2008 R2
  #
  # - Internet Explorer 9
  hotfix_is_vulnerable(os:"6.1",       file:"Mshtml.dll", version:"9.0.8112.20562", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1",       file:"Mshtml.dll", version:"9.0.8112.16455", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / 2008
  #
  # - Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"9.0.8112.20562", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"9.0.8112.16455", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
