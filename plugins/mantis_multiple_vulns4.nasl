#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(19473);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2015/02/11 21:07:49 $");

 script_cve_id(
   "CVE-2005-2556",
   "CVE-2005-2557",
   "CVE-2005-3090",
   "CVE-2005-3091"
  );
 script_bugtraq_id(14604);
 script_osvdb_id(18900, 18901, 18903);

 script_name(english:"Mantis < 1.0.0rc2 Multiple Vulnerabilities");
 script_summary(english:"Checks for the version of Mantis");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
several flaws.");
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of Mantis on the remote host
fails to sanitize user-supplied input to the 'g_db_type' parameter of
the 'core/database_api.php' script.  Provided PHP's 'register_globals'
setting is enabled, an attacker may be able to exploit this to connect
to arbitrary databases as well as scan for arbitrary open ports, even
on an internal network.  In addition, it is reportedly prone to
multiple cross-site scripting issues.");
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=112786017426276&w=2");
 script_set_attribute(attribute:"solution", value:"Upgrade to Mantis 1.0.0rc2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/22");
 script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mantisbt:mantisbt");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("mantis_detect.nasl");
 script_require_keys("installed_sw/MantisBT");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("install_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
if (!can_host_php(port:port))
  audit(AUDIT_WRONG_WEB_SERVER, port, "one that supports PHP.");

app_name = "MantisBT";

install = get_single_install(app_name: app_name, port: port);
install_url = build_url(port:port, qs:install['path']);
version = install['version'];
dir = install['path'];

# Try to exploit one of the flaws.
req = http_get(
  item:
    dir + "/core/database_api.php?" +
    # nb: request a bogus db driver.
    "g_db_type=" + SCRIPT_NAME,
  port:port
);
debug_print("req='", req, "'.");
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
debug_print("res='", res, "'.");
if(res == NULL) audit(AUDIT_RESP_NOT, port, "a keepalive request");

# There's a problem if the requested driver file is missing.
#
# nb: this message occurs even with PHP's display_errors disabled.
if (
  "Missing file: " >< res &&
  "/adodb/drivers/adodb-" + SCRIPT_NAME + ".inc.php" >< res
) {
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  security_warning(port);
  exit(0);
}

# If we're being paranoid...
if (report_paranoia > 1) {
  # Check the version number since the XSS flaws occur independent of
  # register_globals while the exploit above requires it be enabled.
  if(ereg(pattern:"^(0\.19\.[0-3]|^1\.0\.0($|a[123]|rc1))", string:version)) {
    report =
        "\n" +
        "***** Nessus has determined the vulnerability exists on the remote\n" +
        "***** host simply by looking at the version number of Mantis\n" +
        "***** installed there.\n" +
        "\n";

    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    security_warning(port:port, extra:report);
    exit(0);
  }
}

audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url);
