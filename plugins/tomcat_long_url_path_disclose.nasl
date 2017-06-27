#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49701);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/17 15:15:44 $");

  script_cve_id("CVE-2001-0917", "CVE-2002-2009");
  script_bugtraq_id(4557, 3199);
  script_osvdb_id(5526, 34883, 86901);

  script_name(english:"Apache Tomcat Long URL Information Disclosure");
  script_summary(english:"Checks for information disclosure via long URLs.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Apache Tomcat server is affected by an information
disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Apache Tomcat web server is affected by an information
disclosure vulnerability. The full install path of Apache Tomcat can
be obtained by sending an HTTP request which contains a long URL.

Note that there reportedly is an additional install path disclosure
vulnerability in this version of Apache Tomcat; however, Nessus has
not explicitly tested for it.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-4.html#Fixed_in_Apache_Tomcat_4.0.2");
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2001/Nov/190"
  );
  script_set_attribute(attribute:"solution", value:"Update to Apache Tomcat version 4.0.2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("tomcat_error_version.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/tomcat");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("webapp_func.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080);

# Is Tomcat on this port
get_kb_item_or_exit("www/"+port+"/tomcat");

disclosed_path = NULL;
url  = "/" + crap(250) + ".jsp";

r = http_send_recv3(
  port            : port,
  method          : "GET",
  item            : url,
  fetch404        : TRUE,
  follow_redirect : 1,
  exit_on_fail    : TRUE
);

lines = split(r[2]);

foreach line (lines)
{
  pieces = NULL;
  disclosed_path = NULL;

  # *nix 3.x (output can differ on 3.x)
  if (line =~ "^<h2>Location:.*\.jsp<\/h2>JSP file.* \((File name too long|No such file or directory)\)")
  {
    pieces = eregmatch(pattern: 'JSP file "(\\/.*\\/)webapps\\/ROOT\\/.*\\.jsp \\((No such file|File name too)', string: line);
    if (!pieces)
      continue;
    else
    	disclosed_path = pieces[1];
  }

  # *nix 4.x
  if (line =~ "^<html><head><title>.*\/work\/localhost\/.*jsp\.java \(File name too long\)<\/h1>.*<b>type<\/b> Status Report<\/p>")
  {
    pieces = eregmatch(pattern: "<\/p><p><b>message<\/b> <u>(\/.*\/)work\/localhost\/\_\/.*jsp\.java \(File name too long\)<\/u><\/p><p>", string: line);
    if (!pieces)
      continue;
    else
    	disclosed_path = pieces[1];
  }


  # Windows
  if (line =~ "^<html><head><title>.*\\work\\localhost\\.*jsp\.java \(The Filename, directory name, or ")
  {
    pieces = eregmatch(pattern:"<\/p><p><b>description<\/b> <u>The requested resource \(([A-Z]:\\.*\\)work\\localhost\\\_\\.*jsp\.java \(The filename, directory name", string: line);
    if (!pieces)
      continue;
    else
      disclosed_path = pieces[1];
  }

  if (!isnull(disclosed_path))
    break;
}

if (!isnull(disclosed_path))
{
  if (report_verbosity > 0)
  {
    trailer = 'Disclosed path : ' + disclosed_path;
    report = get_vuln_report(items:url, port:port, trailer:trailer);
    security_warning(port: port, extra: report);
  }
  else  security_warning(port);
}
else exit(0, "The Tomcat server listening on port " + port + " is not affected.");
