#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62462);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/19 18:02:19 $");

  script_cve_id(
    "CVE-2012-1766",
    "CVE-2012-1767",
    "CVE-2012-1768",
    "CVE-2012-1769",
    "CVE-2012-1770",
    "CVE-2012-1771",
    "CVE-2012-1772",
    "CVE-2012-1773",
    "CVE-2012-3106",
    "CVE-2012-3107",
    "CVE-2012-3108",
    "CVE-2012-3109",
    "CVE-2012-3110"
  );
  script_bugtraq_id(
    54497,
    54500,
    54504,
    54506,
    54511,
    54531,
    54536,
    54541,
    54543,
    54546,
    54548,
    54550,
    54554
  );
  script_osvdb_id(
    83900,
    83901,
    83902,
    83903,
    83904,
    83905,
    83906,
    83907,
    83908,
    83909,
    83910,
    83911,
    83913,
    83944
  );
  script_xref(name:"CERT", value:"118913");
  script_xref(name:"MSFT", value:"MS12-067");
  script_xref(name:"Secunia", value:"49936");

  script_name(english:"MS12-067: Vulnerabilities in FAST Search Server 2010 for SharePoint Parsing Could Allow Remote Code Execution (2742321)");
  script_summary(english:"Checks version of Sccfa.dll");

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
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2737111");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-067");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for FAST Search Server 2010.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-12-497");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS12-067';
kb = '2553402';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (get_kb_item('SMB/fast_search_server/prodtype') == 'forSharePoint')
  fast_path = get_kb_item('SMB/fast_search_server/path');

if (isnull(fast_path))
  audit(AUDIT_NOT_INST, 'FAST Search Server for SharePoint');

if (fast_path[strlen(fast_path) - 1] != "\")
  fast_path += "\";
fast_path += 'bin';

share = fast_path[0] + '$';
if (!is_accessible_share(share:share))
  audit(AUDIT_SHARE_FAIL, share);

if (hotfix_is_vulnerable(path:fast_path, file:"Sccfa.dll", version:"8.3.7.171", bulletin:bulletin, kb:kb))
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

