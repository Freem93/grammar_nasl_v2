#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56456);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/01/28 22:37:17 $");

  script_cve_id("CVE-2011-2007", "CVE-2011-2008");
  script_bugtraq_id(49997, 49998);
  script_osvdb_id(76223, 76224);
  script_xref(name:"MSFT", value:"MS11-082");
  script_xref(name:"IAVB", value:"2011-B-0127");

  script_name(english:"MS11-082: Vulnerabilities in Host Integration Server Could Allow Denial of Service (2607670)");
  script_summary(english:"Checks version of snadmod.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The Host Integration Server (HIS) installed on the remote host has
multiple denial of service vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Host Integration Server (HIS) installed on the remote
host has multiple denial of service vulnerabilities.  A remote,
unauthenticated attacker could exploit these issues to cause HIS
services to become unresponsive."
  );
  script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/snabase_1-adv.txt");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-082");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for HIS 2004, 2006, 2009, and
2010."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:host_integration_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("microsoft_his_installed.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");



get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS11-082';
kbs = make_list("2578757");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

path = get_kb_item_or_exit('SMB/microsoft_his/path');
match = eregmatch(string:path, pattern:'^([A-Za-z]):');
if (isnull(match)) exit(1, 'Error parsing the HIS install path (' + path + ').');

share = match[1] + '$';
if (!is_accessible_share(share:share))
  exit(1, "Can't connect to "+share+" share.");



if (
  # HIS 2004 SP1
  hotfix_is_vulnerable(path:path, file:"snadmod.dll", version:"6.0.2445.0", min_version:"6.0.0.0", bulletin:bulletin, kb:"2578757") ||

  # HIS 2006 SP1
  hotfix_is_vulnerable(path:path, file:"snadmod.dll", version:"7.0.4220.0", min_version:"7.0.0.0", bulletin:bulletin, kb:"2579597") ||

  # HIS 2009
  # GDR
  hotfix_is_vulnerable(path:path, file:"snadmod.dll", version:"8.0.3850.1", min_version:"8.0.0.0", bulletin:bulletin, kb:"2579598") ||
  # LDR
  #hotfix_is_vulnerable(path:path, file:"snadmod.dll", version:"8.0.3872.2", min_version:"", bulletin:bulletin, kb:"2579598") ||

  # HIS 2010
  # GDR
  hotfix_is_vulnerable(path:path, file:"snadmod.dll", version:"8.5.4317.1", min_version:"8.5.0.0", bulletin:bulletin, kb:"2579599")
  # LDR
  #hotfix_is_vulnerable(path:path, file:"snadmod.dll", version:"8.5.4369.2", min_version:"", bulletin:bulletin, kb:"2579599")
)
{
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
