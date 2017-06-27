#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21607);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/05/16 14:22:07 $");

  script_cve_id("CVE-2006-2437", "CVE-2006-2438");
  script_bugtraq_id(18007);
  script_osvdb_id(25571);

  script_name(english:"Resin viewfile Servlet Arbitrary File Disclosure");
  script_summary(english:"Tries to get the absolute installation path of Resin");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to arbitrary file access.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Resin, an application server.

The installation of Resin on the remote host includes a servlet, named
'viewfile', that lets an unauthenticated, remote attacker view any file
within the web root directory on the affected host.  This could lead to
a loss of confidentiality.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/434145/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.caucho.com/download/changes.xtp");
  script_set_attribute(attribute:"solution", value:
"Either remove the 'resin-doc.war' file and do not deploy using default
configuration files or upgrade to Resin 3.0.19 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:caucho:resin");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/resin");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8080);

# Unless we're paranoid, make sure the banner is from Resin.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner) exit(1, "Unable to get the banner from web server on port "+port+".");
  if ("Resin" >!< banner) exit(1, "The web server on port "+port+" does not appear to be Resin.");
}


# Try to exploit the issue to request a nonexistent class file.
class = string("org/nessus/", SCRIPT_NAME, "/", unixtime(), ".class");
r = http_send_recv3(method:"GET",
  item:string(
    "/resin-doc/viewfile/?",
    "contextpath=/&",
    "servletpath=&",
    "file=WEB-INF/classes/", class
  ),
  port:port,
  exit_on_fail:TRUE
);


# There's a problem if we get an error involving our class name with a full path.
#
# nb: 3.0.19 returns something like:
#     <b>File not found /WEB-INF/classes/org/nessus/resin_viewfile_file_access.nasl/1147831042.class</b></font>
if (
  "<b>File not found" >< r[2] &&
  egrep(pattern:string("found /.+/webapps/ROOT/WEB-INF/classes/", class, "<"), string:r[2])
) security_warning(port);
