#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14178);
 script_version("$Revision: 1.15 $");
 script_cve_id("CVE-2004-2514");
 script_bugtraq_id(10835);
 script_osvdb_id(8319);
 
 script_name(english:"PowerPortal modules/private_messages/index.php Multiple Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is using PowerPortal, a content management system,
written in PHP. 

A vulnerability exists in the remote version of this product that may
allow a remote attacker to inject arbitrary HTML tags in when sending
a private message to a victim user of the remote portal. 

An attacker may exploit this flaw to steal the credentials of another
user on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securiteam.com/unixfocus/5TP0O2ADFK.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/07/28");
 script_cvs_date("$Date: 2015/01/23 22:03:56 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks the version of the remote PowerPortal Installation");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 local_var w, r, version;

 w = http_send_recv3(method:"GET", item:string(loc, "/index.php"), port:port);
 if (isnull(w))exit(0);
 r = w[2];
 if ( egrep(pattern:"Powered by.*PowerPortal", string:r) )
 {
   version = egrep(pattern:"Powered by.*PowerPortal v.*", string:r);
   version = ereg_replace(pattern:".*Powered by.*PowerPortal v([0-9.]*).*", string:version, replace:"\1");
   if ( loc == "") loc = "/";
   set_kb_item(name:"www/" + port + "/powerportal", value:version + " under " + loc );
   if ( ereg(pattern:"^(0\..*|1\.[0-3]([^0-9]|$))", string:version) )
   {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
   }
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

