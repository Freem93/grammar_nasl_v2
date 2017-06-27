#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33273);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/16 14:22:07 $");

  script_cve_id("CVE-2008-2462");
  script_bugtraq_id(29948);
  script_osvdb_id(46515);
  script_xref(name:"CERT", value:"305208");
  script_xref(name:"Secunia", value:"30845");

  script_name(english:"Resin viewfile Servlet file Parameter XSS");
  script_summary(english:"Tries to inject script code through viewfile error");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java Servlet that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Resin, an application server.

The 'viewfile' Servlet included with the version of Resin installed on
the remote host fails to sanitize user input to the 'file' parameter
before including it in dynamic HTML output.  An attacker may be able
to leverage this issue to inject arbitrary HTML and script code into a
user's browser to be executed within the security context of the
affected site.

Note that the affected Servlet is part of the Resin documentation,
which should not be installed on production servers.");
  script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/305208");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Resin or Resin Pro version 3.1.4 / 3.0.25 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:caucho:resin");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/resin");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:8080);

# Unless we're paranoid, make sure the banner is from Resin.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner) exit(1, "Unable to get the banner from web server on port "+port+".");
  if ("Resin" >!< banner) exit(1, "The web server on port "+port+" does not appear to be Resin.");
}


exploit = string("nessus<script>alert('", SCRIPT_NAME, "')</script>");

test_cgi_xss(port: port, ctrl_re: "Resin/", cgi: "/viewfile",
  dirs: make_list("/resin-doc"), qs: "file="+urlencode(str:exploit),
  pass_str: "<b>File not found /"+exploit );

