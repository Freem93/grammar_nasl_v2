#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35224);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id("CVE-2008-0971", "CVE-2008-1094");
  script_bugtraq_id(32867);
  script_osvdb_id(50709, 50912);
  script_xref(name:"Secunia", value:"33164");
  script_xref(name:"EDB-ID", value:"7496");

  script_name(english:"Barracuda Spam Firewall < 3.5.12.007 Multiple Vulnerabilities");
  script_summary(english:"checks firmware version");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains CGI scripts that are affected by
several issues.");
  script_set_attribute(attribute:"description", value:
"The remote Barracuda Spam Firewall device is using a firmware version
prior to version 3.5.12.007. It is, therefore, reportedly affected by
several issues :

  - There is a remote SQL injection vulnerability
    involving the 'pattern_x' parameter (where x=0...n) of
    the 'cgi-bin/index.cgi' script when 'filter_x' is set to
    'search_count_equals'. Successful exploitation requires
    credentials. (CVE-2008-1094)

  - There are multiple cross-site scripting vulnerabilities
    due to a failure to sanitize user input when displaying
    error messages and involving multiple hidden input
    elements. (CVE-2008-0971)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported firmware version.");
  # http://web.archive.org/web/20081225112423/http://dcsl.ul.ie/advisories/02.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d7c04e2");
  # http://web.archive.org/web/20130308061107/http://dcsl.ul.ie/advisories/03.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e6d7709");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Dec/174");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Dec/175");
  script_set_attribute(attribute:"see_also", value:"http://www.barracudanetworks.com/ns/support/tech_alert.php");
  script_set_attribute(attribute:"solution", value:"Update to firmware release 3.5.12.007 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 89);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:barracuda_networks:barracuda_spam_firewall");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

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

install = get_install_from_kb(
  appname : "barracuda_spamfw",
  port    : port,
  exit_on_fail:TRUE
);
dir = install["dir"];
firmware = install["ver"];

if (firmware == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_SERVER_VER, product, port);

fix = "3.5.12.007";
if (ver_compare(ver:firmware, fix:fix, strict:FALSE) < 0)
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  if (report_verbosity > 0)
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
