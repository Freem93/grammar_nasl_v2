#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84085);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/01/28 22:37:18 $");

  script_cve_id("CVE-2015-1764", "CVE-2015-1771", "CVE-2015-2359");
  script_bugtraq_id(75007, 75011, 75013);
  script_osvdb_id(123062, 123063, 123064);
  script_xref(name:"MSFT", value:"MS15-064");

  script_name(english:"MS15-064: Vulnerabilities in Microsoft Exchange Server Could Allow Elevation of Privilege (3062157)");
  script_summary(english:"Checks the version of ExSetup.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Microsoft Exchange server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Microsoft Exchange server is missing a security update. It
is, therefore, affected by multiple vulnerabilities :

  - A server-side request forgery vulnerability exists in
    Microsoft Exchange web applications due to improper
    management of same-origin policy. An attacker can
    exploit this by using a specially crafted web
    application, allowing further attacks to be carried
    out. (CVE-2015-1764)

  - An cross-site request forgery vulnerability exists in
    Microsoft Exchange web applications due to improper
    management of user sessions. A remote attacker can
    exploit this by tricking a user into visiting a
    specially crafted web page, resulting in gaining access
    to sensitive information, impersonating the user's
    identity, or injecting malicious content into the
    victim's web browser. (CVE-2015-1771)

  - An HTML injection vulnerability exists in Microsoft
    Exchange web applications due to not properly sanitizing
    user-supplied HTML strings. A remote attacker can
    exploit this by submitting a crafted script to a target
    site that uses HTML sanitization, resulting in the
    execution of malicious code in the security context of
    the user visiting the site. (CVE-2015-2359)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-064");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Exchange 2013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/06/09");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/10");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:microsoft:exchange_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_exchange_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS15-064';
kb = '3062157';
kbs = make_list(kb);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_install_count(app_name:"Microsoft Exchange", exit_if_zero:TRUE);
install = get_single_install(app_name:"Microsoft Exchange");

path = install["path"];
version = install["version"];
release = install["RELEASE"];
if (release != 150)
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);
cu = install["CU"];
if (isnull(cu) || (cu != 4 && cu != 8))
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);

if (cu == 4) # 2013 SP1 AKA CU4
{
  fixedver = "15.0.847.41";
}
else if (cu == 8) # 2013 CU8
{
  fixedver = '15.0.1076.11';
}
if (hotfix_is_vulnerable(path:hotfix_append_path(path:path, value:"Bin"), file:"ExSetup.exe", version:fixedver, bulletin:bulletin, kb:kb))
{
  set_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
  set_kb_item(name:'www/0/XSS', value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
