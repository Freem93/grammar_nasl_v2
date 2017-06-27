#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42475);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2011/03/07 16:28:07 $");

  script_cve_id("CVE-2009-4038");
  script_bugtraq_id(41894);
  script_xref(name:"OSVDB", value:"59871");
  script_xref(name:"Secunia", value:"37157");

  script_name(english:"Axon Virtual PBX /logon Multiple Parameter XSS");
  script_summary(english:"Tries to inject script code through 'onok' parameter");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts an application that is prone to a cross-
site scripting attack."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote web server is the internal web server component included
with Axon Virtual PBX, a Windows application used to manage phone
calls.

The installed version of this web server fails to sanitize user-
supplied input to the 'onok' parameter of the '/logon' script before
using it to generate dynamic HTML output.

An attacker may be able to leverage this issue to inject arbitrary 
HTML and script code into a user's browser to be executed within the
security context of the affected site."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Axon Virtual PBX 2.13 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/11/11"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/11/12"
  );
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 81);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:81);


# Try to exploit the issue.
alert = string('">', "<script>alert('", SCRIPT_NAME, "')</script>");
vuln = test_cgi_xss(
  port     : port,
  cgi      : "logon",
  dirs     : make_list("/"),
  qs       : "onok="+urlencode(str:alert),
  pass_str : 'name=onok value="'+alert,
  pass2_re : "title>Axon - Login"
);
if (!vuln) exit(0, "The host is not affected.");
