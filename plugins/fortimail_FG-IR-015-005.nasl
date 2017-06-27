#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81670);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/23 20:09:18 $");

  script_cve_id("CVE-2014-8617");
  script_bugtraq_id(72820);
  script_osvdb_id(118921);

  script_name(english:"Fortinet FortiMail < 4.3.9 / 5.0.8 / 5.1.5 / 5.2.3 XSS");
  script_summary(english:"Checks the version of FortiMail.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiMail that is prior to
4.3.9 / 5.0.8 / 5.1.5 / 5.2.3. It is, therefore, affected by a
cross-site scripting vulnerability in the web GUI due to improper
input validation within the Web Action Quarantine Release feature,
specifically for the 'release' parameter of '/module/releasecontrol'.
A remote attacker can exploit this to execute arbitrary HTML or script
code in a user's browser session.");
  script_set_attribute(attribute:"see_also", value:"http://www.fortiguard.com/advisory/FG-IR-15-005");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiMail 4.3.9 / 5.0.8 / 5.1.5 / 5.2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:fortimail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "FortiMail";
model    = get_kb_item_or_exit("Host/Fortigate/model");
version  = get_kb_item_or_exit("Host/Fortigate/version");

# Make sure device is FortiMail.
if (!preg(string:model, pattern:"fortimail", icase:TRUE)) audit(AUDIT_HOST_NOT, "a " + app_name + " device");

if (version =~ "^4\.") fix = "4.3.9";
else if (version =~ "^5\.0\.") fix = "5.0.8";
else if (version =~ "^5\.1\.") fix = "5.1.5";
else if (version =~ "^5\.2\.") fix = "5.2.3";
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
