#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42346);
  script_version("$Revision: 1.9 $");
 script_cvs_date("$Date: 2016/05/04 14:30:40 $");

  script_cve_id("CVE-2009-2959");
  script_bugtraq_id(36100);
  script_osvdb_id(57312);
  script_xref(name:"Secunia", value:"36352");

  script_name(english:"BuildBot WebStatus waterfall 'branch' Parameter XSS");
  script_summary(english:"Attempts a non-persistent XSS attack");

  script_set_attribute(attribute:"synopsis",  value:
"An application running on the remote web server has a cross-site
scripting vulnerability."  );
  script_set_attribute( attribute:"description", value:
"The version of BuildBot WebStatus running on the remote host has a
cross-site scripting vulnerability.  Input to the 'branch' parameter
of the '/waterfall/help' page is not properly sanitized.  A remote
attacker could exploit this by tricking a user into requesting a
malicious URL, which could result in the execution of arbitrary
script code.

This version of BuildBot has several other cross-site scripting
vulnerabilities, though Nessus has not checked for those issues."  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dce5cbdd");
  script_set_attribute(
    attribute:"see_also",
    value:"http://buildbot.net/trac#SecurityAlert"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to BuildBot 0.7.11p3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("buildbot_webstatus_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8010, 8080);
  script_require_keys("www/buildbot_webstatus");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:8010);

install = get_install_from_kb(appname:'buildbot_webstatus', port:port);
if (isnull(install)) exit(0, "BuildBot wasn't detected on port " + port);

xss = '"><script>alert("' + SCRIPT_NAME + '")</script>';
expected_output = '<input type="text" name="branch" value="' + xss;

url = string(install['dir'], '/waterfall/help?branch=', xss);
res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

if (expected_output >< res[2])
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report = get_vuln_report(items:url, port:port);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "The BuildBot install at "+build_url(port:port, qs:install['dir']+"/")+" is not affected.");
