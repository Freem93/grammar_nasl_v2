#
# This test was rewritten by Tenable Network Security, Inc.
#
#  Message-ID: <1642444765.20030319015935@olympos.org>
#  From: Ertan Kurt <mailto:ertank@olympos.org>
#  To: <bugtraq@securityfocus.com>
#  Subject: Some XSS vulns
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB refs (3/27/2009)
# - Changed family (5/21/2009)
# - Added response request and output in report. Modernized the descriptive text. (7/2016)

include("compat.inc");

if (description)
{
  script_id(11447);
  script_version("$Revision: 1.35 $");
  script_cvs_date("$Date: 2016/07/06 19:09:52 $");

  script_cve_id("CVE-2003-1238", "CVE-2003-1371");
  script_bugtraq_id(6916, 6917);
  script_osvdb_id(50552, 52891);
  script_xref(name:"EDB-ID", value:"22276");

  script_name(english:"Nuked-Klan index.php Multiple Module Vulnerabilities");
  script_summary(english:"Determine if Nuked-klan is vulnerable to an XSS attack.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The instance of Nuked-klan running on the remote web server is
affected by multiple vulnerabilities due to a failure to sanitize
user-supplied input to several parameters before using them in the
'Team', 'News', and 'Liens' modules to display dynamic HTML. An
unauthenticated, remote attacker can exploit these issues to execute
arbitrary script code in a user's browser session.

Additionally, an information disclosure vulnerability exists that
allows a remote attacker to disclose the physical path of the
directory in which the application is installed; however, Nessus did
not test for this.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2003/Feb/319");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Mar/265");
  script_set_attribute(attribute:"solution", value:"Contact the author for a patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nuked-klan:nuked-klan");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2016 k-otik.com");

  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (get_kb_item("www/"+port+"/generic_xss"))
  exit(0, "The the web server on port "+port+" is vulnerable to XSS.");

xss_pat = "<script>window.alert('test');</script>";

foreach d (cgi_dirs())
{
  url = d + "/index.php?file=Liens&op=" + raw_string(0x22) + "><script>window.alert('test');</script>";
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if( buf == NULL ) exit(0, "An empty response was received from the web server on port", port);

  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] +200 .*", string:buf) &&
    xss_pat >< buf)
  {
    output = strstr(buf, xss_pat);
    if (isnull(output)) output = buf;

    security_report_v4(
      port     : port,
      severity : SECURITY_WARNING,
      generic  : TRUE,
      request  : make_list(build_url(qs:url, port:port)),
      output   : output,
      xss      : TRUE
    );
    exit(0);
  }
}
exit(0, "The web server on port "+port+" is not affected.");
