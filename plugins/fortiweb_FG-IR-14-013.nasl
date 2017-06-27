#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(74105);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/04/23 20:09:18 $");

  script_cve_id("CVE-2014-3115");
  script_bugtraq_id(67235);
  script_osvdb_id(106688);
  script_xref(name:"CERT", value:"902790");

  script_name(english:"Fortinet FortiWeb < 5.2.0 Multiple XSRF Vulnerabilities");
  script_summary(english:"Checks the version of FortiWeb");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is affected by multiple cross-site request forgery
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host running FortiWeb prior to 5.2.0. It is, therefore,
affected by multiple cross-site request forgery (XSRF) vulnerabilities
in the web UI due to a lack of XSRF token protection. A remote,
unauthenticated attacker could potentially exploit this vulnerability
to perform administrative actions."
  );
  script_set_attribute(attribute:"see_also",value:"http://www.fortiguard.com/advisory/FG-IR-14-013");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Fortinet FortiWeb 5.2.0 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date",value:"2014/05/02");
  script_set_attribute(attribute:"patch_publication_date",value:"2014/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/20");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:fortinet:fortiweb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "FortiWeb";
model = get_kb_item_or_exit("Host/Fortigate/model");
version = get_kb_item_or_exit("Host/Fortigate/version");
fix = '5.2.0';

# Make sure device is FortiWeb.
if (!preg(string:model, pattern:"fortiweb", icase:TRUE)) audit(AUDIT_HOST_NOT, "a " + app_name + " device");

# Treating all currently supported versions as potentially vulnerable.
# 4.3 and up.
if (
  ver_compare(ver:version, fix:'4.3', strict:FALSE) >= 0 &&
  ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = 0;
  set_kb_item(name:"www/"+port+"/XSRF", value:TRUE);
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
