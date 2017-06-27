#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84959);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/07/18 15:54:01 $");

  script_cve_id(
    "CVE-2015-0228",
    "CVE-2015-0253",
    "CVE-2015-3183",
    "CVE-2015-3185"
  );
  script_bugtraq_id(
    73041,
    75963,
    75964,
    75965
  );
  script_osvdb_id(
    119066,
    119904,
    123122,
    123123,
    128186
  );

  script_name(english:"Apache 2.4.x < 2.4.16 Multiple Vulnerabilities");
  script_summary(english:"Checks the version in the server response header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache 2.4.x installed on the
remote host is prior to 2.4.16. It is, therefore, affected by the
following vulnerabilities :

  - A flaw exists in the lua_websocket_read() function in
    the 'mod_lua' module due to incorrect handling of
    WebSocket PING frames. A remote attacker can exploit
    this, by sending a crafted WebSocket PING frame after a
    Lua script has called the wsupgrade() function, to crash
    a child process, resulting in a denial of service
    condition. (CVE-2015-0228)

  - A NULL pointer dereference flaw exists in the
    read_request_line() function due to a failure to
    initialize the protocol structure member. A remote 
    attacker can exploit this flaw, on installations that
    enable the INCLUDES filter and has an ErrorDocument 400
    directive specifying a local URI, by sending a request
    that lacks a method, to cause a denial of service
    condition. (CVE-2015-0253)

  - A flaw exists in the chunked transfer coding
    implementation due to a failure to properly parse chunk
    headers. A remote attacker can exploit this to conduct
    HTTP request smuggling attacks. (CVE-2015-3183)

  - A flaw exists in the ap_some_auth_required() function
    due to a failure to consider that a Require directive
    may be associated with an authorization setting rather
    than an authentication setting. A remote attacker can
    exploit this, if a module that relies on the 2.2 API
    behavior exists, to bypass intended access restrictions.
    (CVE-2015-3185)

  - A flaw exists in the RC4 algorithm due to an initial
    double-byte bias in the keystream generation. An
    attacker can exploit this, via Bayesian analysis that
    combines an a priori plaintext distribution with
    keystream distribution statistics, to conduct a
    plaintext recovery of the ciphertext. Note that RC4
    cipher suites are prohibited per RFC 7465. This issue
    was fixed in Apache version 2.4.13; however, 2.4.13,
    2.4.14, and 2.4.15 were never publicly released.
    (VulnDB 128186)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.4.16");
  script_set_attribute(attribute:"see_also", value:"http://httpd.apache.org/security/vulnerabilities_24.html");
  # http://svn.apache.org/viewvc/httpd/httpd/tags/2.4.13/CHANGES?revision=1683584&view=markup
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ec9a07a");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc7465");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.16 or later. Alternatively, ensure that
the affected modules are not in use.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/23");

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
  version =~ "^2\.4\.([0-9]|1[0-2])($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.4.16' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, version);
