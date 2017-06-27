#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81126);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/04 14:21:28 $");

  script_cve_id(
    "CVE-2013-5704",
    "CVE-2014-3581",
    "CVE-2014-3583",
    "CVE-2014-8109"
  );
  script_bugtraq_id(
    66550,
    71656,
    71657,
    73040
  );
  script_osvdb_id(
    105190,
    112168,
    114570,
    115375
  );

  script_name(english:"Apache 2.4.x < 2.4.12 Multiple Vulnerabilities");
  script_summary(english:"Checks the version in the server response header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache 2.4.x running on the
remote host is prior to 2.4.12. It is, therefore, affected by the
following vulnerabilities :

  - A flaw exists in module mod_headers that can allow HTTP
    trailers to replace HTTP headers late during request
    processing, which a remote attacker can exploit to
    inject arbitrary headers. This can also cause some
    modules to function incorrectly or appear to function
    incorrectly. (CVE-2013-5704)

  - A NULL pointer dereference flaw exists in module
    mod_cache. A remote attacker, using an empty HTTP
    Content-Type header, can exploit this vulnerability to
    crash a caching forward proxy configuration, resulting
    in a denial of service if using a threaded MPM.
    (CVE-2014-3581)

  - A out-of-bounds memory read flaw exists in module
    mod_proxy_fcgi. An attacker, using a remote FastCGI
    server to send long response headers, can exploit this
    vulnerability to cause a denial of service by causing
    a buffer over-read. (CVE-2014-3583)

  - A flaw exists in module mod_lua when handling a
    LuaAuthzProvider used in multiple Require directives
    with different arguments. An attacker can exploit this
    vulnerability to bypass intended access restrictions.
    (CVE-2014-8109)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.4.12");
  script_set_attribute(attribute:"see_also", value:"http://httpd.apache.org/security/vulnerabilities_24.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.12 or later. Alternatively, ensure that
the affected modules are not in use.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("apache_http_version.nasl");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# Make sure this is Apache.
get_kb_item_or_exit('www/'+port+'/apache');

# Check if we could get a version first, then check if it was
# backported
version = get_kb_item_or_exit('www/apache/'+port+'/version', exit_code:1);
backported = get_kb_item_or_exit('www/apache/'+port+'/backported', exit_code:1);

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "Apache web server");
source = get_kb_item_or_exit('www/apache/'+port+'/source', exit_code:1);

# Check if the version looks like either ServerTokens Major/Minor was used.
if (version =~ '^2(\\.[34])?$') audit(AUDIT_VER_NOT_GRANULAR, "Apache", port, version);

# This plugin is only concerned with Apache 2.4 (and its associated development branch).
if (version !~ "^2\.[34][^0-9]") audit(AUDIT_WRONG_WEB_SERVER, port, "Apache 2.4.x");

if (
  version =~ "^2\.3($|[^0-9])" ||
  version =~ "^2\.4\.([0-9]|10)($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.4.12' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, version);
