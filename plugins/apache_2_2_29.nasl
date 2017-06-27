#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77531);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/19 17:45:32 $");

  script_cve_id(
    "CVE-2013-5704",
    "CVE-2014-0118",
    "CVE-2014-0226",
    "CVE-2014-0231"
  );
  script_bugtraq_id(66550, 68678, 68742, 68745);
  script_osvdb_id(105190, 109216, 109231, 109234);
  script_xref(name:"EDB-ID", value:"34133");

  script_name(english:"Apache 2.2.x < 2.2.28 Multiple Vulnerabilities");
  script_summary(english:"Checks the version in the server response header.");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache 2.2.x running on the
remote host is prior to 2.2.28. It is, therefore, affected by the
following vulnerabilities :

  - An flaw exists within the 'mod_headers' module which
    allows a remote attacker to inject arbitrary headers.
    This is done by placing a header in the trailer portion
    of data being sent using chunked transfer encoding.
    (CVE-2013-5704)

  - An flaw exists within the 'mod_deflate' module when
    handling highly compressed bodies. Using a specially
    crafted request, a remote attacker can exploit this to
    cause a denial of service by exhausting memory and CPU
    resources. (CVE-2014-0118)

  - The 'mod_status' module contains a race condition that
    can be triggered when handling the scoreboard. A remote
    attacker can exploit this to cause a denial of service,
    execute arbitrary code, or obtain sensitive credential
    information. (CVE-2014-0226)

  - The 'mod_cgid' module lacks a time out mechanism. Using
    a specially crafted request, a remote attacker can use
    this flaw to cause a denial of service by causing child
    processes to linger indefinitely, eventually filling up
    the scoreboard. (CVE-2014-0231)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-236/");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.2.29");
  script_set_attribute(attribute:"see_also", value:"http://httpd.apache.org/security/vulnerabilities_22.html");
  script_set_attribute(attribute:"see_also", value:"http://martin.swende.se/blog/HTTPChunked.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.2.29 or later.

Note that version 2.2.28 was never officially released.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/04");

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

app_name = "Apache";

# Make sure this is Apache.
get_kb_item_or_exit('www/'+port+'/apache');

# Check if we could get a version first, then check if it was
# backported
version = get_kb_item_or_exit('www/apache/'+port+'/version', exit_code:1);
backported = get_kb_item_or_exit('www/apache/'+port+'/backported', exit_code:1);

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, app_name);
source = get_kb_item_or_exit('www/apache/'+port+'/source', exit_code:1);

# Check if the version looks like either ServerTokens Major/Minor was used.
if (version =~ '^2(\\.2)?$') audit(AUDIT_VER_NOT_GRANULAR, app_name, port, source);

# This plugin is only concerned with Apache 2.2
if (version !~ "^2\.2[^0-9]") audit(AUDIT_WRONG_WEB_SERVER, port, app_name + " 2.2.x");

fixed = '2.2.28';
display_fixed = '2.2.29';
if (ver_compare(ver:version, fix:fixed) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + display_fixed +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
