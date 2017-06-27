#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21247);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2016/12/08 20:42:13 $");

  script_cve_id("CVE-2006-0015");
  script_bugtraq_id(17452);
  script_osvdb_id(24518);
  script_xref(name:"MSFT", value:"MS06-017");

  script_name(english:"MS06-017: FrontPage fpadmdll.dll Multiple Parameter XSS (917627)");
  script_summary(english:"Checks version of FrontPage's fpadmdll.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a server extension that is affected by
a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft FrontPage Server Extensions 2002 / SharePoint
Team Services on the remote host is affected by a cross-site scripting
(XSS) vulnerability due to improper sanitization of user-supplied
input to the 'operation', 'command', and 'name' parameters to file
/_vti_bin/_vti_adm/fpadmdll.dll before using the input to generate
dynamic HTML. A remote attacker can exploit this issue to cause
arbitrary HTML and script code to be executed in a user's browser
session in the context of the affected website.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-017");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Frontapage 2002 for XP and
2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:frontpage_server_extensions");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

bulletin = 'MS06-017';
kbs = make_list("908981", "911831", "911701");

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


if (hotfix_check_sp(xp:3, win2003:2) <= 0) exit(0);
fp_root = get_kb_item ("Frontpage/2002/path");
if (!fp_root) exit (0);

if (is_accessible_share())
{
  if (hotfix_check_fversion(file:"fpadmdll.dll", path:fp_root + "\isapi\_vti_adm", version:"10.0.6790.0") == HCF_OLDER)
  {
    security_warning(get_kb_item("SMB/transport"));
    set_kb_item(name: 'www/0/XSS', value: TRUE);
  }
  hotfix_check_fversion_end();
}
else if (
  hotfix_missing(name:"908981") > 0 &&
  hotfix_missing(name:"911831") > 0 &&
  hotfix_missing(name:"911701") > 0
) {
  security_warning(get_kb_item("SMB/transport"));
  set_kb_item(name:"SMB/Missing/MS06-017", value:TRUE);
  set_kb_item(name: 'www/0/XSS', value: TRUE);
  }
