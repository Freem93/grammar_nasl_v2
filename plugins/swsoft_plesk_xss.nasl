#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14369);
 script_version("$Revision: 1.23 $");

 script_cve_id("CVE-2004-2702");
 script_bugtraq_id(11024);
 script_xref(name:"OSVDB", value:"9149");
 script_xref(name:"Secunia", value:"12368");
 
 script_name(english:"Plesk Reloaded login_up.php3 login_name Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Plesk Reloaded (from SWsoft), a web-based
system administration tool. 

The remote version of this software is vulnerable to a cross-site
scripting attack because of its failure to sanitize user input to the
'login_name' parameter of the 'login_up.php3' script.  This issue can
be used to take advantage of the trust between a client and server
allowing the malicious user to execute malicious JavaScript on the
client's machine." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2004/Aug/1055" );
 script_set_attribute(attribute:"solution", value:
"Reportedly the vendor has issued patches, which are available via its
website or the software's autoupdate feature." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/24");
 script_cvs_date("$Date: 2016/11/03 20:40:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Checks for the presence of an XSS bug in Plesk Reloaded";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("cross_site_scripting.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP", "Settings/ParanoidReport");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, php: 1, no_xss: 1);

test_cgi_xss( port: port, cgi: "/login_up.php3", 
	      qs: "login_name=<script>foo</script>",
	      pass_str: '<script>foo</script>' );
