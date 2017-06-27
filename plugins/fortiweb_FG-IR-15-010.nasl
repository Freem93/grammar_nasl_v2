#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83031);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/20 20:49:17 $");

  script_bugtraq_id(74195);
  script_osvdb_id(120939, 120940, 120941);

  script_name(english:"Fortinet FortiWeb < 5.3.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of FortiWeb.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host running a version of FortiWeb prior to 5.3.5. It is,
therefore, affected by multiple vulnerabilities :

  - A command injection vulnerability exists due to a flaw
    that occurs when an administrator is executing reports.
    An authenticated, remote attacker can exploit this to
    execute arbitrary system commands. (VulnDB 120939)

  - A cross-site scripting vulnerability exists due to
    improper sanitization of a parameter in the auto
    update service page. A remote, authenticated attacker
    can exploit this to execute arbitrary script code in a
    user's browser session. Note that this vulnerability
    only affects the 5.x version branch. (VulnDB 120940)

  - A security bypass vulnerability exists due to the
    the password field for the FTP backup page having
    HTML form autocomplete enabled. A local attacker can
    exploit this to bypass FortiWeb's authentication.
    (VulnDB 120941)");
  script_set_attribute(attribute:"see_also", value:"http://www.fortiguard.com/advisory/FG-IR-15-010");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiWeb 5.3.5 or later. Alternatively, apply the
workaround as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/04/16");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/23");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:fortinet:fortiweb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

model = get_kb_item_or_exit("Host/Fortigate/model");
version = get_kb_item_or_exit("Host/Fortigate/version");

app_name = "FortiWeb";
fix = '5.3.5';
port = 0;

# Make sure device is FortiWeb.
if (!preg(string:model, pattern:app_name, icase:TRUE)) audit(AUDIT_HOST_NOT, "a " + app_name + " device");

# Treating all currently supported versions as potentially vulnerable.
# 4.3 and up. 5.x versions also need the XSS KB to be set.
if (
  ver_compare(ver:version, fix:'4.3', strict:FALSE) >= 0 &&
  ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (version =~ "^5\.")
  {
    set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  }

  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';

    security_warning(extra:report, port:port);
  }
  else security_warning(port:port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
