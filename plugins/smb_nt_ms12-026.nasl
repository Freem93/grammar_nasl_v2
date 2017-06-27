#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58658);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2012-0146", "CVE-2012-0147");
  script_bugtraq_id(52903, 52909);
  script_osvdb_id(81131, 81132);
  script_xref(name:"MSFT", value:"MS12-026");

  script_name(english:"MS12-026: Vulnerabilities in Forefront Unified Access Gateway (UAG) Could Allow Information Disclosure (2663860)");
  script_summary(english:"Checks version of Whlfilter.dll");

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
remote host has multiple vulnerabilities :

  - A spoofing vulnerability that could allow an attacker to
    redirect a victim to a malicious website.  An attacker
    would have to trick the victim into clicking a specially
    crafted link in order to trigger the vulnerability.
    (CVE-2012-0146)

  - A flaw that could allow an unauthenticated user to
    access the default website of the UAG server from the
    external network. (CVE-2012-0147)"
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-026");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for UAG 2010 SP1 and UAG 2010
SP 1 Update 1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:forefront_unified_access_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("forefront_uag_installed.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS12-026';
kbs = make_list('2649261', '2649262');

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

path = get_kb_item_or_exit('SMB/forefront_uag/path');
path += "\von\bin\";
match = eregmatch(string:path, pattern:'^([A-Za-z]):');
if (isnull(match)) exit(1, 'Error parsing the UAG install path (' + path + ').');

share = match[1] + '$';
if (!is_accessible_share(share:share))
  exit(1, "Can't connect to "+share+" share.");

if (
  # UAG 2010 SP1
  hotfix_is_vulnerable(path:path, file:"Whlfilter.dll", version:"4.0.1753.10076", min_version:"4.0.1752.10000", bulletin:bulletin, kb:"2649261") ||

  # UAG 2010 SP1 Update 1
  hotfix_is_vulnerable(path:path, file:"Whlfilter.dll", version:"4.0.1773.10190", min_version:"4.0.1773.10100", bulletin:bulletin, kb:"2649262")
)
{
  set_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, 'The host is not affected.');
}
