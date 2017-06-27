#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# This script is released under the GNU GPLv2
#

# Changes by Tenable:
# - Revised plugin title, added CVE / OSVDB refs (3/25/2009)
# - Revised plugin description-fixed typo (06/02/2011)


include("compat.inc");

if(description)
{
 script_id(18290);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2005-1361", "CVE-2005-1363", "CVE-2005-1622");
 script_bugtraq_id(13385, 13384, 13383, 13382, 13639);
 script_osvdb_id(15870, 15871, 16706);

 script_name(english:"MetaCart E-Shop productsByCategory.ASP Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected
by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the MetaCart e-Shop, an online store
written in ASP. 

Due to a lack of user input validation, the remote version of this
software is vulnerable to various SQL injection and cross-site
scripting attacks. 

An attacker may exploit these flaws to execute arbitrary SQL commands
against the remote database or to perform a cross-site scripting
attack using the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Apr/426" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Apr/427" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Apr/428" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Apr/429" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/May/195" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/26");
 script_cvs_date("$Date: 2017/02/23 16:41:17 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 summary["english"] = "MetaCart E-Shop productsByCategory.ASP XSS and SQL injection Vulnerabilities";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_family(english:"CGI abuses");
 script_copyright(english:"Copyright (C) 2005-2017 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/ASP");
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if ( ! can_host_asp(port:port) ) exit(0);

function check(url)
{
 local_var req, res;

 req = http_get(item:url +"/productsByCategory.asp?intCatalogID=3'&strCatalog_NAME=Nessus", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);

 # Check for the SQL injection
 if ("80040e14" >< res && "cat_ID = 3'" >< res )
 {
     security_hole(port);
     set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
     set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
     exit(0);
 }
}

foreach dir ( make_list (cgi_dirs()) )
{
  check(url:dir);
}
