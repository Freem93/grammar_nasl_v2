#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80398);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/24 13:12:23 $");

  script_cve_id(
    "CVE-2013-5704",
    "CVE-2014-0118",
    "CVE-2014-0226",
    "CVE-2014-0231",
    "CVE-2014-3021",
    "CVE-2014-3566",
    "CVE-2014-4770",
    "CVE-2014-4816",
    "CVE-2014-6164",
    "CVE-2014-6166",
    "CVE-2014-6167",
    "CVE-2014-6174",
    "CVE-2014-8890"
  );
  script_bugtraq_id(
    66550,
    68678,
    68742,
    68745,
    69980,
    69981,
    70239,
    70574,
    70582,
    71834,
    71836,
    71837,
    71850
  );
  script_osvdb_id(
    105190,
    109216,
    109231,
    109234,
    111737,
    111738,
    113153,
    113251,
    116076,
    116077,
    116078,
    116079,
    116080
  );
  script_xref(name:"CERT", value:"577193");

  script_name(english:"IBM WebSphere Application Server 8.5 < Fix Pack 8.5.5.4 Multiple Vulnerabilities (POODLE)");
  script_summary(english:"Reads the version number from the SOAP port.");

  script_set_attribute(attribute:"synopsis", value:"The remote application server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Application Server running on the remote host is
version 8.5 prior to Fix Pack 8.5.5.4. It is, therefore, affected by
the following vulnerabilities :

  - Multiple errors exist related to the included IBM HTTP
    server that can allow remote code execution or denial
    of service. (CVE-2013-5704, CVE-2014-0118,
    CVE-2014-0226, CVE-2014-0231 / PI22070)

  - An unspecified error exists related to HTTP headers
    that can allow information disclosure. (CVE-2014-3021
    / PI08268)

  - An error exists related to the way SSL 3.0 handles
    padding bytes when decrypting messages encrypted using
    block ciphers in cipher block chaining (CBC) mode. A
    man-in-the-middle attacker can decrypt a selected byte
    of a cipher text in as few as 256 tries if they are able
    to force a victim application to repeatedly send the
    same data over newly created SSL 3.0 connections. This
    is also known as the 'POODLE' issue. (CVE-2014-3566 /
    PI28435, PI28436, PI28437)

  - An unspecified input validation errors exist related to
    the administrative console that can allow cross-site
    scripting and cross-site request forgery attacks.
    (CVE-2014-4770, CVE-2014-4816 / PI23055)

  - An unspecified error exists that can allow OpenID and
    OpenID Connect cookies to be spoofed, allowing
    information disclosure. (CVE-2014-6164 / PI23430)

  - An error exists related to the Communications Enabled
    Applications (CEA) service that can allow XML External
    Entity Injection (XXE) attacks leading to information
    disclosure. This only occurs if CEA is enabled. By
    default this is disabled. (CVE-2014-6166 / PI25310)

  - An input validation error exists related to session
    input using URL rewriting that can allow cross-site
    scripting attacks. (CVE-2014-6167 / PI23819)

  - An error exists related to the administrative console
    that can allow 'click-jacking' attacks. (CVE-2014-6174 /
    PI27152)

  - An error exists related to deployment descriptor
    security constraints and ServletSecurity annotations on
    a servlet that can allow privilege escalation. Note that
    this issue only affects the 'Liberty Profile'.
    (CVE-2014-8890 / PI29911)");
  # Sec bulletin
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21690185");
  script_set_attribute(attribute:"see_also", value:"http://www-304.ibm.com/support/docview.wss?uid=swg21672428");
  # Downloads
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24038539");
  # Fix list
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27036319#8554");
  # CVE-2014-3566 details (via IBM)
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21687173");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-236/");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Apply Fix Pack 4 for (8.5.5.4) or later.

Note that the following Interim Fixes are available :

  - CVE-2013-5704, CVE-2014-0118, CVE-2014-0226, and
    CVE-2014-0231 are corrected in IF PI22070.

  - CVE-2014-3566 is corrected in various IFs.
    Consult IBM document 'swg21687173' for details.

  - CVE-2014-4770 and CVE-2014-4816 are corrected in
    IF PI23055.

  - CVE-2014-6166 is corrected in IF PI25310.

  - CVE-2014-8890 is corrected in IF PI29911.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("websphere_detect.nasl");
  script_require_ports("Services/www", 8880, 8881);
  script_require_keys("www/WebSphere");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8880, embedded:0);

version = get_kb_item_or_exit("www/WebSphere/"+port+"/version");
source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

app_name = "IBM WebSphere Application Server";

if (version !~ "^8\.5([^0-9]|$)")
  audit(AUDIT_NOT_LISTEN, app_name + " 8.5", port);

if (version =~ "^[0-9]+(\.[0-9]+)?$")
  audit(AUDIT_VER_NOT_GRANULAR, app_name, port, version);

fixed = '8.5.5.4';

if (ver_compare(ver:version, fix:fixed, strict:FALSE) < 0)
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  set_kb_item(name: 'www/'+port+'/XSRF', value: TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
