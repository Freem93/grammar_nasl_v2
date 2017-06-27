#
# Written by Astharot <astharot@zone-h.org>
# 

# Changes by Tenable:
# - Revised plugin title (4/2/2009)


include("compat.inc");

if(description)
{
 script_id(12042);
 script_version("$Revision: 1.21 $");

 script_cve_id("CVE-2004-2175");
 script_bugtraq_id(9574, 12159);
 script_osvdb_id(3817, 3832);

 script_name(english:"ReviewPost PHP Pro Multiple Script SQL Injections"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
multiple SQL injection attacks." );
 script_set_attribute(attribute:"description", value:
"ReviewPost PHP Pro, a web-based software that manages user's opinions,
is installed on the remote web server. 

The installed version fails to sanitize user input to the 'product'
parameter of the 'showproduct.php' script and the 'cat' parameter of
the 'showcat.php' script before using it in a database query.  An
unauthenticated attacker can leverage these issues to manipulate such
queries to disclose sensitive information and gain administrative
access to the application." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/352598/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for a patch." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/02/04");
 script_cvs_date("$Date: 2015/09/24 23:21:20 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 
 summary["english"] = "SQL Injection";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2015 Astharot");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);


function check(dir)
{
 local_var report, req, res, url;

 url = dir + "/showproduct.php?product=1'";
 req = http_get(item:url, port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if (isnull(res)) exit(0);
 
 if ("id,user,userid,cat,date,title,description,manu,keywords,bigimage,bigimage2,bigimage3,views,approved,rating" >< res ) {
	if (report_verbosity > 0)
	{
	  report = string(
	    "\n",
	    "Nessus was able to verify the issue exists using the following URL :\n",
	    "\n",
	    "  ", build_url(port:port, qs:url), "\n"
	  );
	  security_hole(port:port, extra:report);
	}
	else security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
	}

 url = dir + "/showcat.php?cat=1'";
 req = http_get(item:url, port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if (isnull(res)) exit(0);
 
 if ("id,catname FROM rp_categories" >< res ) {
	if (report_verbosity > 0)
	{
	  report = string(
	    "\n",
	    "Nessus was able to verify the issue exists using the following URL :\n",
	    "\n",
	    "  ", build_url(port:port, qs:url), "\n"
	  );
	  security_hole(port:port, extra:report);
	}
	else security_hole(port);

	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
	}
}


foreach dir (cgi_dirs()) 
 {
  check(dir:dir);
 }
