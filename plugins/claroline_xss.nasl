#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(16318);
 script_version ("$Revision: 1.14 $");
 script_bugtraq_id(12449);
 script_osvdb_id(13465);
 
 script_name(english:"Claroline add_course.php Multiple Parameter XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a PHP script that is prone to cross-site
scipting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote version of Claroline fails to sanitize user input to
several parameters of the 'add_course.php' script.  Using a
specially crafted URL, an attacker may be able to exploit this issue
to perform cross-site scripting attacks against users of the affected
application." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/advisories/14131/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade as necessary to Claroline 1.5.3 and apply the
claroline153fix01.zip patch referenced in the advisory above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/04");
 script_cvs_date("$Date: 2015/01/13 20:37:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks if Claroline is vulnerable to a XSS attack");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("claroline_detect.nasl", "cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/claroline");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/claroline"));
if (isnull(install)) exit(0);

matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (isnull(matches)) exit(0);

dir = matches[2];
r = http_send_recv3(method:"GET", item:dir + "/add_course.php?intitule=<script>foo<script>", port:port);
if (isnull(r)) exit(0);

if( "/create_course/add_course.php?intitule=<script>foo</script>>" >< r[2] )
    {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    }
  
