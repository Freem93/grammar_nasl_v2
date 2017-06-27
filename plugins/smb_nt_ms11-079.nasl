#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56453);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/01/28 22:37:17 $");

  script_cve_id(
    "CVE-2011-1895",
    "CVE-2011-1896",
    "CVE-2011-1897",
    "CVE-2011-1969",
    "CVE-2011-2012"
  );
  script_bugtraq_id(49972, 49974, 49979, 49980, 49983);
  script_osvdb_id(76233, 76234, 76235, 76236, 76237);
  script_xref(name:"TRA", value:"TRA-2011-07");
  script_xref(name:"MSFT", value:"MS11-079");

  script_name(english:"MS11-079: Vulnerabilities in Microsoft Forefront Unified Access Gateway Could Cause Remote Code Execution (2544641)");
  script_summary(english:"Checks version of whlfilter.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote Windows host has multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Forefront Unified Access Gateway (UAG) running on the
remote host has multiple vulnerabilities in the Web Monitor
component :

  - An HTTP response splitting vulnerability in
    ExcelTable.asp. (CVE-2011-1895)

  - A reflected XSS in ExcelTable.asp. (CVE-2011-1896)

  - A reflected XSS in Default.asp. (CVE-2011-1897)

  - A code execution vulnerability in a signed Java applet.
    Users that access the UAG server from a Java-enabled
    web browser are affected. (CVE-2011-1969)

  - Processing a null session cookie can cause the web
    server to become unresponsive. (CVE-2011-2012)"
  );
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2011-07");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-079");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for UAG 2010, UAG 2010 Update
1, UAG 2010 Update 2, and UAG 2010 SP1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:forefront_unified_access_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS11-079';
kbs = make_list("2522482");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

path = get_kb_item_or_exit('SMB/forefront_uag/path');
path += "\von\bin\";
match = eregmatch(string:path, pattern:'^([A-Za-z]):');
if (isnull(match)) exit(1, 'Error parsing the UAG install path (' + path + ').');

share = match[1] + '$';
if (!is_accessible_share(share:share))
  exit(1, "Can't connect to "+share+" share.");



# For all four, min_version is the file version in a vanilla install
if (
  # UAG 2010 RTM
  hotfix_is_vulnerable(path:path, file:"Whlfilter.dll", version:"4.0.1101.63", min_version:"4.0.1101.0", bulletin:bulletin, kb:"2522482") ||

  # UAG 2010 Update 1
  hotfix_is_vulnerable(path:path, file:"Whlfilter.dll", version:"4.0.1152.163", min_version:"4.0.1152.100", bulletin:bulletin, kb:"2522483") ||

  #UAG 2010 Update 2
  hotfix_is_vulnerable(path:path, file:"Whlfilter.dll", version:"4.0.1269.284", min_version:"4.0.1269.200", bulletin:bulletin, kb:"2522484") ||

  #UAG 2010 SP1
  hotfix_is_vulnerable(path:path, file:"Whlfilter.dll", version:"4.0.1752.10073", min_version:"4.0.1752.10000", bulletin:bulletin, kb:"2522485")
)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, 'The host is not affected.');
}
