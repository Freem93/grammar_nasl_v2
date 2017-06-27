#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57791);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/10/19 20:19:15 $");

  script_cve_id(
    "CVE-2011-3368",
    "CVE-2011-3607",
    "CVE-2011-4317",
    "CVE-2012-0021",
    "CVE-2012-0031",
    "CVE-2012-0053",
    "CVE-2012-4557"
  );
  script_bugtraq_id(49957, 50494, 50802, 51407, 51705, 51706, 56753);
  script_osvdb_id(76079, 76744, 77310, 78293, 78555, 78556, 89275);

  script_name(english:"Apache 2.2.x < 2.2.22 Multiple Vulnerabilities");
  script_summary(english:"Checks version in Server response header.");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache 2.2.x installed on the
remote host is prior to 2.2.22. It is, therefore, potentially affected
by the following vulnerabilities :

  - When configured as a reverse proxy, improper use of the
    RewriteRule and ProxyPassMatch directives could cause
    the web server to proxy requests to arbitrary hosts.
    This could allow a remote attacker to indirectly send
    requests to intranet servers.
    (CVE-2011-3368, CVE-2011-4317)

  - A heap-based buffer overflow exists when mod_setenvif
    module is enabled and both a maliciously crafted 
    'SetEnvIf' directive and a maliciously crafted HTTP 
    request header are used. (CVE-2011-3607)

  - A format string handling error can allow the server to
    be crashed via maliciously crafted cookies.
    (CVE-2012-0021)

  - An error exists in 'scoreboard.c' that can allow local
    attackers to crash the server during shutdown.
    (CVE-2012-0031)

  - An error exists in 'protocol.c' that can allow 
    'HTTPOnly' cookies to be exposed to attackers through
    the malicious use of either long or malformed HTTP
    headers. (CVE-2012-0053)

  - An error in the mod_proxy_ajp module when used to 
    connect to a backend server that takes an overly long 
    time to respond could lead to a temporary denial of 
    service. (CVE-2012-4557)

Note that Nessus did not actually test for these flaws, but instead 
has relied on the version in the server's banner.");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.2.22");
  script_set_attribute(attribute:"see_also", value:"http://httpd.apache.org/security/vulnerabilities_22.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache version 2.2.22 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("apache_http_version.nasl");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);

  exit(0);
}

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

if (report_paranoia < 2 && backported) exit(1, "Security Patches may have been backported.");
source = get_kb_item_or_exit('www/apache/'+port+'/source', exit_code:1);

# Check if the version looks like either ServerTokens Major/Minor
# was used
if (version =~ '^2(\\.2)?$') exit(1, "The banner from the Apache server listening on port "+port+" - "+source+" - is not granular enough to make a determination.");

fixed_ver = '2.2.22';
if (version =~ '^2\\.2' && ver_compare(ver:version, fix:fixed_ver) == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_ver + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "Apache "+version+" is listening on port "+port+" and is not affected.");
