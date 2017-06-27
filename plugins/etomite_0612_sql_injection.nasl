#
#       This script was written by Justin Seitz <jms@bughunter.ca>
#	Per Justin : GPLv2
#
# Changes by Tenable:
# - Revised plugin title (1/02/2009)
# - Revised plugin title (9/6/2011)


include("compat.inc");

if(description)
{
 # set script identifiers

 script_id(23724);
 script_version("$Revision: 1.18 $");

 script_cve_id("CVE-2006-6048");
 script_bugtraq_id(21135);
 script_osvdb_id(30442);

 script_name(english:"Etomite CMS index.php id Parameter SQL Injection");
 summary["english"] = "Tries to generate a SQL error with Etomite CMS";
 family["english"] = "CGI abuses";

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote web server is running Etomite CMS, a PHP-based content
management system. 

The version of Etomite CMS installed on the remote host fails to
sanitize input to the 'id' parameter before using it in the
'index.php' script in a database query.  Provided PHP's
'magic_quotes_gpc' setting is disabled, an unauthenticated attacker
can exploit this issue to manipulate SQL queries, possibly leading to
disclosure of sensitive data, attacks against the underlying database,
and the like." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/451838/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"No patches or upgrades have been reported by the vendor at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/11/16");
 script_cvs_date("$Date: 2011/09/06 18:54:56 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2006-2011 Justin Seitz");

 script_family(english:family["english"]);

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
port = get_http_port(default:80);

#
# verify we can talk to the web server, if not exit
#

if(!get_port_state(port)) exit(0);
if(!can_host_php(port:port)) exit(0);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);

#
# create list of directories to scan
#


# Loop through directories.

if (thorough_tests) dirs = list_uniq(make_list("/etomite","/cms", cgi_dirs()));
else dirs = make_list(cgi_dirs());

#
# Iterate through the list
#

injectstring = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789_", length:10);

foreach dir (dirs) {

	#
	#
	#       Attack: Attempt to inject our random string.
	#
	#
	
	attackreq = http_get(item:string(dir, "/index.php?id=", injectstring, "'"),port:port);
	attackres = http_keepalive_send_recv(port:port, data:attackreq, bodyonly:TRUE);
	if (attackres == NULL) exit(0);
	
	sqlstring = "";
	if(string("etomite_site_content.id = '", injectstring) >< attackres) {
            if (report_verbosity > 1) {
			sqlstring = attackres;
			if("<span id='sqlHolder'>" >< sqlstring) sqlstring = strstr(sqlstring,"SELECT");
			
			if("</span></b>" >< sqlstring) sqlstring = sqlstring - strstr(sqlstring, "</span></b>");			


			info = string("The version of Etomite CMS installed in directory '", dir, "'\n",
	        	"is vulnerable to this issue. Here is the resulting SQL string\n",
			"from the remote host when using a test string of '",injectstring,"'  :\n\n", sqlstring);
		     	security_warning(port: port, extra: info);
            }
            else
	      security_warning(port:port);
	    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
            exit(0);
	}
}
