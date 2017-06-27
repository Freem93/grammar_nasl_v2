#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76622);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/19 17:45:32 $");

  script_cve_id(
    "CVE-2014-0117",
    "CVE-2014-0118",
    "CVE-2014-0226",
    "CVE-2014-0231",
    "CVE-2014-3523"
  );
  script_bugtraq_id(68740, 68745, 68678, 68742, 68747);
  script_osvdb_id(109216, 109230, 109231, 109232, 109234);
  script_xref(name:"EDB-ID", value:"34133");

  script_name(english:"Apache 2.4.x < 2.4.10 Multiple Vulnerabilities");
  script_summary(english:"Checks version in Server response header.");

  script_set_attribute(attribute:"synopsis", value:"The remote web server may be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache 2.4.x running on the
remote host is prior to 2.4.10. It is, therefore, affected by the
following vulnerabilities :

  - A flaw exists in the 'mod_proxy' module that may allow
    an attacker to send a specially crafted request to a
    server configured as a reverse proxy that may cause
    the child process to crash. This could potentially
    lead to a denial of service attack. (CVE-2014-0117)

  - A flaw exists in  the 'mod_deflate' module when request
    body decompression is configured. This could allow a
    remote attacker to cause the server to consume
    significant resources. (CVE-2014-0118)

  - A flaw exists in the 'mod_status' module when a
    publicly accessible server status page is in place.
    This could allow an attacker to send a specially
    crafted request designed to cause a heap buffer
    overflow. (CVE-2014-0226)

  - A flaw exists in the 'mod_cgid' module in which CGI
    scripts that did not consume standard input may be
    manipulated in order to cause child processes to
    hang. A remote attacker may be able to abuse this
    in order to cause a denial of service.
    (CVE-2014-0231)

  - A flaw exists in WinNT MPM versions 2.4.1 to 2.4.9 when
    using the default AcceptFilter. An attacker may be able
    to specially craft requests that create a memory leak in
    the application and may eventually lead to a denial of
    service attack. (CVE-2014-3523)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.4.10");
  script_set_attribute(attribute:"see_also", value:"http://httpd.apache.org/security/vulnerabilities_24.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.10 or later. Alternatively, ensure that
the affected modules are not in use.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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
if (version =~ '^2(\\.[34])?$') exit(1, "The banner from the Apache server listening on port "+port+" - "+source+" - is not granular enough to make a determination.");

# This plugin is only concerned with Apache 2.4 (and its associated development branch).
if (version !~ "^2\.[34][^0-9]") audit(AUDIT_WRONG_WEB_SERVER, port, "Apache 2.4.x");

if (
  version =~ "^2\.3($|[^0-9])" ||
  version =~ "^2\.4\.[0-9]($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.4.10' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, version);
