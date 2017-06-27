#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32434);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/10/07 13:30:46 $");

  script_cve_id("CVE-2008-2333");
  script_bugtraq_id(29340);
  script_osvdb_id(45611);
  script_xref(name:"Secunia", value:"30362");

  script_name(english:"Barracuda Spam Firewall cgi-bin/ldap_test.cgi email Parameter XSS");
  script_summary(english:"Checks firmware version");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its firmware version, the remote Barracuda Spam Firewall
device fails to filter input to the 'email' parameter of the
'/cgi-bin/ldap_test.cgi' script before using it to generate dynamic
content.  An unauthenticated, remote attacker may be able to leverage
this issue to inject arbitrary HTML or script code into a user's
browser to be executed within the security context of the affected
site.

Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported firmware version.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/May/564");
  script_set_attribute(attribute:"see_also", value:"http://www.barracudanetworks.com/ns/support/tech_alert.php");
  script_set_attribute(attribute:"solution", value:
"Either configure the device to limit access to the web management
application by IP address or update to firmware release 3.5.11.025 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:barracuda_networks:barracuda_spam_firewall");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("barracuda_detect.nasl");
  script_require_ports("Services/www", 8000);
  script_require_keys("www/barracuda_spamfw");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8000, embedded:TRUE);
product = "Barracuda Spam Firewall";

# Identify and check the firmware version.
install = get_install_from_kb(
  appname : "barracuda_spamfw",
  port    : port,
  exit_on_fail:TRUE
);
dir = install["dir"];
firmware = install["ver"];

if (firmware == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_SERVER_VER, product, port);

fix = "3.5.11.025";
if (ver_compare(ver:firmware, fix:fix, strict:FALSE) < 0)
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  if (report_verbosity)
  {
    report =
      '\n Product           : ' + product +
      '\n URL               : ' + build_url(qs:dir, port:port) +
      '\n Installed Version : ' + firmware +
      '\n Fixed Version     : ' + fix + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, product, port, firmware);
