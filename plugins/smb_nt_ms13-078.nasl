#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(69837);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/01/28 22:37:18 $");

  script_cve_id("CVE-2013-3137");
  script_bugtraq_id(62185);
  script_osvdb_id(97138);
  script_xref(name:"MSFT", value:"MS13-078");
  script_xref(name:"IAVB", value:"2013-B-0101");

  script_name(english:"MS13-078: Vulnerability in FrontPage Could Allow Information Disclosure (2825621)");
  script_summary(english:"Checks version of FrontPage");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is affected by an information disclosure
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The host has a version of Microsoft FrontPage installed that is
affected by an information disclosure vulnerability that could allow a
remote attacker to view the contents of a file."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS13-078");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for FrontPage 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:frontpage");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS13-078';
kb = "2825621";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

tested_shares = make_array();

frontpage_2003_paths = get_kb_list("SMB/Office/FrontPage/11.0.*/ProductPath");
if (isnull(frontpage_2003_paths)) audit(AUDIT_NOT_INST, "Microsoft FrontPage 2003");

vuln = 0;

foreach key (keys(frontpage_2003_paths))
{
  path = frontpage_2003_paths[key];
  # clean up escapes
  path = str_replace(find:"\\", replace:"\", string:path);
  path -= "\Frontpg.exe";

  share = hotfix_path2share(path:path);
  if (isnull(tested_shares[share])) tested_shares[share] = is_accessible_share(share:share);

  if (!tested_shares[share]) continue;

  if (hotfix_is_vulnerable(file:"Frontpg.exe", version:"11.0.8339.0", min_version:"11.0.0.0", path:path, bulletin:bulletin, kb:kb)) vuln++;
  NetUseDel(close:FALSE);
}

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
