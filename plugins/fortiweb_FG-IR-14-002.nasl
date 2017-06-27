#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73530);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/04/23 20:09:18 $");

  script_cve_id("CVE-2013-7181");
  script_bugtraq_id(65303);
  script_osvdb_id(102820);
  script_xref(name:"CERT", value:"593118");

  script_name(english:"Fortinet FortiWeb 5.x < 5.1.0 XSS");
  script_summary(english:"Checks the version of FortiWeb.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running FortiWeb 5.x prior to 5.1.0. It is,
therefore, affected by a cross-site scripting vulnerability in the web
UI due to a failure to sanitize user-supplied input to the 'filter'
parameter in the '/user/ldap_user/add' script. An attacker could
potentially exploit this vulnerability to execute arbitrary JavaScript
in the context of the end-user's browser.");
  script_set_attribute(attribute:"see_also", value:"http://www.fortiguard.com/advisory/FG-IR-14-002");
  script_set_attribute(attribute:"solution", value:"Upgrade to Fortinet FortiWeb 5.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortiweb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version", "Host/Fortigate/build");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "FortiWeb";
model = get_kb_item_or_exit("Host/Fortigate/model");
version = get_kb_item_or_exit("Host/Fortigate/version");
build = get_kb_item_or_exit("Host/Fortigate/build");
vuln = FALSE;

# Make sure device is FortiWeb.
if (!preg(string:model, pattern:"fortiweb", icase:TRUE)) audit(AUDIT_HOST_NOT, "a " + app_name + " device");

# Only 5.x is affected.
if (version =~ "^5\.")
{
  max_affected = "5.0.3";
  max_affected_build = 57;
  fix = "5.1.0";
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

# If build number is available, this is the safest comparison.
# Otherwise compare version numbers.
if (build !~ "Unknown")
{
  if (int(build) <= max_affected_build) vuln = TRUE;
}
else if (ver_compare(ver:version, fix:max_affected, strict:FALSE) <= 0) vuln = TRUE;

if (vuln)
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
