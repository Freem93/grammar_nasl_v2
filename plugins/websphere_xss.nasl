#
# (C) Tenable Network Security, Inc.
#

# base on cross_site_scripting.nasl, from various people

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID


include("compat.inc");

if (description)
{
 script_id(11010);
 script_version("$Revision: 1.30 $");
 script_cvs_date("$Date: 2016/05/06 17:22:03 $");

 script_bugtraq_id(2401);
 script_osvdb_id(54837);

 script_name(english:"IBM WebSphere Traversal Error Page XSS");
 script_summary(english:"Determine if the remote host is vulnerable to an XSS attack");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is itself prone to cross-site scripting
attacks.");
 script_set_attribute(attribute:"description", value:
"The remote web server seems to be vulnerable to cross-site scripting
attacks because it fails to sanitize input supplied as a filename when
displaying an error page. 

The vulnerability would allow an attacker to make the server present
the user with the attacker's JavaScript/HTML code.  Since the content
is presented by the server, the user will give it the trust level of
the server (for example, the trust level of banks, shopping centers,
etc would usually be high).");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of WebSphere.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/06/08");
 
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/ibm-http");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

xss = string("<script>alert('", SCRIPT_NAME, "')</script>");
w = http_send_recv3(method:"GET", item:string("/../", xss), port:port);
if (isnull(w)) exit(0);
if(xss >< w[2])
{
 security_warning(port);
 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}

