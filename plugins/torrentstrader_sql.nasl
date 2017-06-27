#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14615);
 script_version("$Revision: 1.11 $");
 script_bugtraq_id(11087);
 script_osvdb_id(9510);
 
 script_name(english:"TorrentTrader download.php id Parameter SQL Injection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has a PHP script that is affected by SQL injection
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running TorrentTrader, a web-based BitTorrent
tracker. 

The remote version of this software is vulnerable to a SQL injection
attack that may allow an attacker to inject arbitrary SQL statements
in the remote database." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/01");
 script_cvs_date("$Date: 2011/03/12 01:05:17 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_summary(english:"Checks for the presence of SQL injection in TorrentTrader");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
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

# TorrentTrader must be installed under /
res = http_send_recv3(method:"GET", item:"/download.php?id='", port:port);
if(isnull(res))exit(0);
if(egrep(pattern:".*mysql_result\(\).*MySQL.*download\.php", string:res[2]) )
{
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  exit(0);
}
