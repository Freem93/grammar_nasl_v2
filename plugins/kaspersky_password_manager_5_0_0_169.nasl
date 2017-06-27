#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62800);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/03 17:40:02 $");

  script_bugtraq_id(54760);

  script_name(english:"Kaspersky Password Manager 5.x < 5.0.0.169 HTML Injection");
  script_summary(english:"Checks version of Kaspersky Password Manager");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a password manager installed that is
affected by an HTML injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Kaspersky Password Manager installed on the remote
Windows host is 5.x prior to 5.0.0.169.  As such, it is potentially
affected by an HTML injection vulnerability. 

A remote attacker can trick a user into visiting a malicious website and
into saving malicious code from the site when the application's password
management features are used.  Later, the user could trigger the
malicious code when using Password Manager's export functionality.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/523735");
  script_set_attribute(attribute:"solution", value:"Upgrade to Kaspersky Password Manager 5.0.0.169 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:kaspersky:kaspersky_password_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("kaspersky_password_manager_installed.nasl");
  script_require_keys("SMB/Kaspersky/PasswordManager/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_kb_item('SMB/transport');

version = get_kb_item_or_exit("SMB/Kaspersky/PasswordManager/Version");
if (version == UNKNOWN_VER) audit(AUDIT_VER_FAIL, "Kaspersky Password Manager");

if (version !~ "^5\.") audit(AUDIT_NOT_INST, "Kaspersky Password Manager 5.x");

path = get_kb_item_or_exit("SMB/Kaspersky/PasswordManager/Path");

fixed_version = '5.0.0.169';
if (ver_compare(ver:version, fix:fixed_version) < 0)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'Kaspersky Password Manager', version, path);
