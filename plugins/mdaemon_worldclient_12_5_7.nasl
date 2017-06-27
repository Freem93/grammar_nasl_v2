#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62125);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/06/20 20:49:18 $");

  script_cve_id("CVE-2012-2584");
  script_bugtraq_id(54885);
  script_osvdb_id(84695, 84796);
  script_xref(name:"EDB-ID", value:"20357");

  script_name(english:"MDaemon WorldClient < 12.5.7 Multiple XSS Vulnerabilities");
  script_summary(english:"Checks version of MDaemon");
 
  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote webmail client is affected by multiple cross-site scripting
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of MDaemon's WorldClient is
earlier than 12.5.7 and is, therefore, affected by the following
cross-site scripting vulnerabilities :

  - Input supplied in body of an email is not properly
    sanitized before being presented to the user. Specially
    crafted email messages that can exploit this error
    contain CSS expression properties with comments inside
    'STYLE' attributes inside either image or other
    elements. Another method is to use the 'innerHTML'
    attribute in XML documents. This is a persistent
    cross-site scripting issue. (CVE-2012-2584)

  - Input supplied via unspecified vectors is not properly
    sanitized before being presented to the user.
    (VulnDB #84796)"
  );
  script_set_attribute(attribute:"see_also", value:"http://files.altn.com/MDaemon/Release/relnotes_en.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to MDaemon 12.5.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:alt-n:mdaemon");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 3000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:3000);
    
res = http_get_cache(item:"/", port:port, exit_on_fail:TRUE); 
if (
  'form action="/WorldClient.dll' >!< res &&
  "MDaemon" >!< res &&
  "/WorldClient" >!< res
) audit(AUDIT_WRONG_WEB_SERVER, port, "MDaemon WorldClient");

report_url = build_url(port:port, qs:"/");

# Extract the version number from the login page.
version_str = strstr(res, "/WorldClient v");
version_str = version_str - strstr(version_str, " &copy;");
matches = eregmatch(pattern:"^\/WorldClient v([0-9.]+)$", string:version_str);
if (isnull(matches)) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, "MDaemon WorldClient", port);

version = matches[1];

fixed_version = "12.5.7";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report = 
      '\n  URL                : ' + report_url +
      '\n  Installed version  : ' + version + 
      '\n  Fixed version      : ' + fixed_version + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_LISTEN_NOT_VULN, "MDaemon WorldClient", port, version);
