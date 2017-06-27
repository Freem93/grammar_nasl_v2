#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12057);
 script_version ("$Revision: 1.21 $");
 script_bugtraq_id(9659);
 script_xref(name:"OSVDB", value:"3966");
 
 script_name(english:"ASP Portal User Profile XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI that is vulnerable to a cross-
site scripting issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the ASP Portal CGI suite.

There is a cross-site scripting issue in this suite that may allow an
attacker to steal your users cookies." );
 script_set_attribute(attribute:"solution", value:
"See http://www.aspportal.net/downloadsviewer.asp?theurl=38" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/02/16");
 script_cvs_date("$Date: 2017/02/21 14:37:31 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks for ASP Portal");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2017 Tenable Network Security, Inc."); 
 script_family(english:"CGI abuses : XSS");
 script_dependencie("find_service1.nasl", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/ASP", "Settings/ParanoidReport");
 exit(0);
}

# The script code starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, no_xss: 1, asp: 1);

test_cgi_xss(port: port, cgi: "/index.asp", qs: "inc=<script>foo</script>",
  pass_str: "<script>foo</script>");
