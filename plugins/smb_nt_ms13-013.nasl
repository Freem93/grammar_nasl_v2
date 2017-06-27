#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64574);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/04/23 21:44:06 $");

  script_cve_id("CVE-2012-3214", "CVE-2012-3217");
  script_bugtraq_id(55977, 55993);
  script_osvdb_id(86389, 86392);
  script_xref(name:"MSFT", value:"MS13-013");
  script_xref(name:"IAVA", value:"2013-A-0044");

  script_name(english:"MS13-013: Vulnerabilities in FAST Search Server 2010 for SharePoint Parsing Could Allow Remote Code Execution (2784242)");
  script_summary(english:"Checks version of Sccdu.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host is affected by multiple code execution
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is using a vulnerable version of FAST Search Server
2010 for SharePoint.  When the Advanced Filter Pack is enabled,
vulnerable versions of the Oracle Outside In libraries are used to parse
files.  An attacker could exploit this by uploading a malicious file to
a site using FAST Search to index, which could result in arbitrary code
execution."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-013");
  script_set_attribute(
    attribute:"solution",
    value:"Microsoft has released a set of patches for FAST Search Server 2010."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "fast_search_server_installed.nasl");
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

bulletin = 'MS13-013';
kb = '2553234';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (get_kb_item('SMB/fast_search_server/prodtype') == 'forSharePoint') fast_path = get_kb_item('SMB/fast_search_server/path');
if (isnull(fast_path)) audit(AUDIT_NOT_INST, 'FAST Search Server for SharePoint');

if (fast_path[strlen(fast_path) - 1] != "\") fast_path += "\";
fast_path += 'bin';

share = fast_path[0] + '$';
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (hotfix_is_vulnerable(path:fast_path, file:"Sccdu.dll", version:"8.3.7.239", bulletin:bulletin, kb:kb))
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
