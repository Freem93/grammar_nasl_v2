#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50530);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/06/30 19:55:38 $");

  script_cve_id("CVE-2010-2732", "CVE-2010-2733", "CVE-2010-2734", "CVE-2010-3936");
  script_bugtraq_id(44631, 44632, 44633, 44634);
  script_osvdb_id(69092, 69093, 69094, 69095);
  script_xref(name:"IAVA", value:"2010-A-0159");
  script_xref(name:"MSFT", value:"MS10-089");

  script_name(english:"MS10-089: Vulnerabilities in Forefront Unified Access Gateway (UAG) Could Allow Elevation of Privilege (2316074)");
  script_summary(english:"Checks version of WhlFilter.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:"An application on the remote host has multiple vulnerabilities"
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Forefront Unified Access Gateway (UAG) running on the
remote host has multiple vulnerabilities :

  - An unspecified redirection spoofing vulnerability, which
    could result in users being redirected from the UAG server
    to a similar looking, malicious server. (CVE-2010-2732)

  - An unspecified non-persistent XSS in UAG.
    (CVE-2010-2733)

  - An unspecified non-persistent XSS in the UAG Mobile
    Portal Website. (CVE-2010-2734)

  - An unspecified non-persistent XSS in Signurl.asp.
    (CVE-2010-3936)"
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-089");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for UAG 2010, UAG 2010 Update
1, and UAG 2010 Update 2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:forefront_unified_access_gateway");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("forefront_uag_installed.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");



get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-089';
kbs = make_list("2433585");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


path = get_kb_item_or_exit('SMB/forefront_uag/path');
path += "\von\bin\";
match = eregmatch(string:path, pattern:'^([A-Za-z]):');
if (isnull(match)) exit(1, 'Error parsing UAG install path: ' + path);

share = match[1] + '$';
if (!is_accessible_share(share:share)) exit(1, 'is_accessible_share(share:'+share+') failed.');


# For all three, min_version is the file version in a vanilla install
if (
  # UAG 2010 (no updates)
  hotfix_is_vulnerable(path:path, file:"Whlfilter.dll", version:"4.0.1101.52", min_version:"4.0.1101.0", bulletin:bulletin, kb:"2433585") ||

  # UAG 2010 Update 1
  hotfix_is_vulnerable(path:path, file:"Whlfilter.dll", version:"4.0.1152.150", min_version:"4.0.1152.100", bulletin:bulletin, kb:"2433584") ||

  #UAG 2010 Update 2
  hotfix_is_vulnerable(path:path, file:"Whlfilter.dll", version:"4.0.1269.250", min_version:"4.0.1269.200", bulletin:bulletin, kb:"2418933")
)
{
  set_kb_item(name: 'www/0/XSS', value: TRUE);
  set_kb_item(name:'SMB/Missing/MS10-089', value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, 'The host is not affected.');
}
