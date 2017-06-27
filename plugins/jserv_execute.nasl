#
# Written by Michael Scheidell <scheidell at secnap.net>
# based on a script written by Hendrik Scholz <hendrik@scholz.net> 
#
# See the Nessus Scripts License for details
#
#

# Changes by Tenable:
# - Revised plugin title, removed incorrect CVE/OSVDB, added correct OSVDB, added see also link (4/30/09)


include("compat.inc");

if(description)
{
 script_id(10925);
 script_version("$Revision: 1.17 $");
 script_osvdb_id(44618);
 script_cvs_date("$Date: 2015/10/21 20:34:20 $");
 
 script_name(english:"Oracle JSP Apache/Jserv Path Translation Arbitrary JSP File Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to several flaws." );
 script_set_attribute(attribute:"description", value:
"Detects Vulnerability in the execution of JSPs outside doc_root.

A potential security vulnerability has been discovered in Oracle JSP 
releases 1.0.x through 1.1.1 (in Apache/Jserv). This vulnerability 
permits access to and execution of unintended JSP files outside the 
doc_root in Apache/Jserv. For example, accessing
http://www.example.com/a.jsp//..//..//..//..//..//../b.jsp
will execute b.jsp outside the doc_root instead of a.jsp if there is a 
b.jsp file in the matching directory.

Further, Jserv Releases 1.0.x - 1.0.2 have additional vulnerability:

Due to a bug in Apache/Jserv path translation, any URL that looks like:
http://host:port/servlets/a.jsp, makes Oracle JSP execute 
'd:\servlets\a.jsp' if such a directory path actually exists. Thus, a 
URL virtual path, an actual directory path and the Oracle JSP name
(when using Oracle Apache/JServ) must match for this potential 
vulnerability to occur.

Vulnerable systems:
Oracle8i Release 8.1.7, iAS Release version 1.0.2
Oracle JSP, Apache/JServ Releases version 1.0.x - 1.1.1" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OJSP Release 1.1.2.0.0, available on Oracle
Technology Network's OJSP website." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/03/27");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Oracle Jserv Server type and version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2015 Michael Scheidell");
 script_family(english:"Databases");
 script_dependencie("find_service1.nasl", "httpver.nasl", "no404.nasl",  "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("global_settings.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
str = http_get_cache(item:"/", port:port);
if(ereg(pattern:".*apachejserv/1\.(0|1\.[0-1][^0-9])",string:str))
      security_warning(port);
