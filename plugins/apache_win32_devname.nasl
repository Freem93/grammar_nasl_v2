#
# (C) Tenable Network Security, Inc.
#

#
# The real DoS will be performed by plugin#10930, so we just check
# the banner 
#


include("compat.inc");

if(description)
{
 script_id(11209);
 script_version("$Revision: 1.20 $");
 script_cve_id("CVE-2003-0016");
 script_bugtraq_id(6659);
 script_osvdb_id(9708, 9709);
 script_xref(name:"Secunia", value:"20493");
 
 script_name(english:"Apache < 2.0.44 DOS Device Name Multiple Remote Vulnerabilities (Code Exec, DoS)");
 script_summary(english:"Checks for version of Apache");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple remote vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of
Apache for Windows that is older than 2.0.44.

There are several flaws in this version that allow
an attacker to crash this host or even execute arbitrary
code remotely, but it only affects WindowsME and Windows9x.

*** Note that Nessus solely relied on the version number
*** of the remote server to issue this warning. This might
*** be a false positive." );
 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC48645" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache 2.0.44 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/01/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/01/20");
 script_cvs_date("$Date: 2015/08/04 20:57:14 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:apache:http_server");
script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("backport.inc");

port = get_http_port(default:80);
banner = get_backport_banner(banner:get_http_banner(port: port));
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/2\.0\.(([0-3][0-9][^0-9])|(4[0-3][^0-9])).*Win32.*", string:serv))
 {
   security_hole(port);
 }
