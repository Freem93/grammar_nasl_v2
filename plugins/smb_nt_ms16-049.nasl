#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90442);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/07/18 20:50:59 $");

  script_cve_id("CVE-2016-0150");
  script_bugtraq_id(85908);
  script_osvdb_id(136978);
  script_xref(name:"MSFT", value:"MS16-049");
  script_xref(name:"IAVB", value:"2016-B-0066");

  script_name(english:"MS16-049: Security Update for HTTP.sys (3148795)");
  script_summary(english:"Checks file version of HTTP.sys.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by a denial of service vulnerability in the HTTP
2.0 protocol stack (HTTP.sys) due to improper parsing of HTTP 2.0
requests. An unauthenticated, remote attacker can exploit this
vulnerability, via a specially crafted HTTP packet, to cause the
system to become unresponsive, resulting in a denial of service
condition.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms16-049");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-049';
kbs = make_list('3147461','3147458');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"Http.sys", version:"10.0.10240.16766", min_version:"10.0.10240.16000", dir:"\system32\drivers", bulletin:bulletin, kb:kbs[0]) ||
  # Windows 10 1511
  hotfix_is_vulnerable(os:"10", sp:0, file:"Http.sys", version:"10.0.10586.212", min_version:"10.0.10586.0", dir:"\system32\drivers", bulletin:bulletin, kb:kbs[1])
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
