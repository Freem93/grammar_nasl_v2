#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
 script_id(16045);
 script_version ("$Revision: 1.14 $");
 script_cvs_date("$Date: 2015/02/11 21:07:50 $");

 script_cve_id("CVE-2004-1318");
 script_bugtraq_id(12053);
 script_osvdb_id(12516);

 script_name(english:"Namazu < 2.0.14 Multiple Vulnerabilities");
 script_summary(english:"Checks for the version of Namazu");

 script_set_attribute(
  attribute:'synopsis',
  value:'The remote service is affected by multiple vulnerabilities.'
 );
 script_set_attribute(
  attribute:'description',
  value:
"The remote host is running Namazu - a web-based search engine.

The remote version of this software has various flaws that may allow
an attacker to perform a cross-site scripting attack using the remote
host or to execute arbitrary code on the remote system with the
privileges of the web server."
 );
 script_set_attribute(attribute:'solution', value:"Upgrade to Namazu 2.0.14 or newer");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/12/15");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:namazu:namazu");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

foreach dir ( cgi_dirs() )
{
 w = http_send_recv3(method:"GET", item:dir + "/namazu.cgi", port:port);
 if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
 buf = strcat(w[0], w[1], '\r\n', w[2]);

 str = egrep(pattern:'<strong><a href="http://www.namazu.org/">Namazu</a> <!-- VERSION --> .* <!-- VERSION --></strong>', string:buf);
 if ( ! str ) exit(0);
 version = ereg_replace(pattern:".*<!-- VERSION --> v?(.*) <!-- VERSION -->.*", string:str, replace:"\1");
 set_kb_item(name:"www/" + port + "/namazu", value:version + " under " + dir);

 if ( ereg(pattern:"^([01]\.|2\.0\.(1[0-3]|[0-9])($|[^0-9]))", string:version) )
 {
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
 }
}
