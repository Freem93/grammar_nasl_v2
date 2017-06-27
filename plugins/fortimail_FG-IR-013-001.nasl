#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73524);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/04/23 20:09:18 $");

  script_cve_id("CVE-2013-1471");
  script_bugtraq_id(57601);
  script_osvdb_id(89745, 89746);
  script_xref(name:"EDB-ID", value:"24435");

  script_name(english:"Fortinet FortiMail < 4.3.4 / 5.0.0 Multiple XSS");
  script_summary(english:"Checks version of FortiMail");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple cross-site scripting
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running FortiMail prior to 4.3.4 / 5.0.0. It is,
therefore, affected by multiple cross-site scripting vulnerabilities
due to a failure to sanitize user-supplied input in the web UI.

Specifically, flaws exist in the 'ipmask', 'username', 'address', and
'url' parameters of the '/admin/FEAdmin.html' script as well as the
'SysInterfaceCollection', 'PersonalBlackWhiteList',
'SystemBlackWhiteList', and 'AsBounceverifyKeyCollection' parameters
of the '/admin/FEAdmin.htm' script.

An attacker could potentially exploit this vulnerability to execute
arbitrary JavaScript in the context of the end-user's browser.");
  script_set_attribute(attribute:"see_also", value:"http://www.fortiguard.com/advisory/FG-IR-013-001");
  script_set_attribute(attribute:"solution", value:"Upgrade to Fortinet FortiMail 4.3.4 / 5.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:fortimail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "FortiMail";
model = get_kb_item_or_exit("Host/Fortigate/model");
version = get_kb_item_or_exit("Host/Fortigate/version");

# Make sure device is FortiMail.
if (!preg(string:model, pattern:"fortimail", icase:TRUE)) audit(AUDIT_HOST_NOT, "a " + app_name + " device");

# Check for affected models.
if (
  '-200D' >!< model &&
  '-400C' >!< model &&
  '-VM2000' >!< model &&
  '-2000B' >!< model &&
  '-5002B' >!< model
  ) audit(AUDIT_OS_NOT, "affected FortiMail model");


# Only 4.x and 5.x are affected.
if (version =~ "^4\.") fix = "4.3.4";
else if (version =~ "^5\.") fix = "5.0.0";
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = 0;
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
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
