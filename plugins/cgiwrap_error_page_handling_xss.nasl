#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33279);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2008-2852");
  script_bugtraq_id(29811);
  script_osvdb_id(46405);
  script_xref(name:"Secunia", value:"30765");

  script_name(english:"CGIWrap Charset Specification Weakness Error Message XSS");
  script_summary(english:"Checks for charset in Content-Type response header for an error page");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by a
cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running CGIWrap, a wrapper for CGI scripts to
provide enhanced security.

The version of CGIWrap installed on the remote host does not specify
a charset when responses are for error pages. An attacker may be able
to leverage this issue to inject arbitrary HTML and script code into
a user's browser to be executed whithin the security context of the
affected site. This only affects some browsers like Internet
Explorer." );
 script_set_attribute(attribute:"see_also", value:"http://jvn.jp/en/jp/JVN45389864/index.html" );
 script_set_attribute(attribute:"see_also", value:"http://cgiwrap.sourceforge.net/changes.html" );
 script_set_attribute(attribute:"solution", value:
"Update to version 4.1 of CGIWrap." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/06/30");
 script_cvs_date("$Date: 2011/03/14 21:48:02 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  r = http_send_recv3(method:"GET", port: port,
    item:string(dir, "/cgiwrap/", SCRIPT_NAME));
  if (isnull(r)) exit(0);

  res = strcat(r[0], r[1], '\r\n', r[2]);
  headers = r[1];
  content_type = "";
  foreach line (split(headers, keep:FALSE))
  {
    if (line =~ "^Content-type:")
    {
      content_type = line;
      break;
    }
  }
  if (
    content_type && 
    "charset=" >!< content_type &&
    "CGIWrap Error" >< res)
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}

