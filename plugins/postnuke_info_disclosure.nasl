#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(11482);
 script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2014/07/11 19:38:17 $");

 script_name(english:"PostNuke Members_List Module Information Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PostNuke. It is possible to use the CMS to 
determine the full path to its installation on the server or the name of
the database used, by doing a request like :

/modules.php?op=modload&name=Members_List&file=index&letter=All&sortby=foobar

An attacker may use these flaws to gain a more intimate knowledge of the
remote host." );
 script_set_attribute(attribute:"solution", value:
"Change the members list privileges to admins only, or disable the 
members list module completely." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/26");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:postnuke_software_foundation:postnuke");
 script_end_attributes();

 script_summary(english:"Determine if a remote host is vulnerable to the opendir.php vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2001-2014 Tenable Network Security, Inc.");
 script_dependencie("postnuke_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/postnuke");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/postnuke" );
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb );
dir = stuff[2];

if(!can_host_php(port:port))exit(0);

u = string(dir, "/modules.php?op=modload&name=Members_List&file=index&letter=All&sortby=foobar");
r = http_send_recv3(method: "GET",item: u, port:port);
if (isnull(r)) exit(0);
 
res = r[0]+r[1]+'\r\n'+r[2];
if("Program: /" >< res && "Database: " >< res && "Unknown column 'foobar'" >< res)
    	security_warning(port, extra: strcat(
'\nThe following URL exhibits the flaw :\n\n', build_url(port: port, qs: u), '\n'));
