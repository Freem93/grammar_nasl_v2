#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15708);
 script_version("$Revision: 1.11 $"); 

 script_cve_id("CVE-1999-0068", "CVE-1999-0346");
 script_bugtraq_id(713);
 script_osvdb_id(3396, 3397);
 
 script_name(english:"PHP < 3.0 mylog.html/mlog.html Arbitrary File Access");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be read on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHP/FI.

The remote version of this software contains a flaw in 
the files mylog.html/mlog.html that can allow a remote attacker 
to view arbitrary files on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 3.0 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "1997/10/19");
 script_cvs_date("$Date: 2012/08/27 22:34:36 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:php:php");
script_end_attributes();

 
 summary["english"] = "Checks PHP mylog.html/mlog.html arbitrary file access";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);

foreach dir ( make_list(cgi_dirs(), "/php") )
{
	foreach htmlfile (make_list("/mylog.html", "/mlog.html"))
	{
	  req = http_get(port:port, item:dir + htmlfile + "?screen=/etc/passwd");
 	  res = http_keepalive_send_recv(port:port, data:req);
 	  if ( res == NULL ) 
		exit(0);
 	  if ( egrep( pattern:"root:.*:0:[01]:.*", string:res) )
	  {
	 	security_warning(port);
	 	exit(0);
	  }
	 }
}
