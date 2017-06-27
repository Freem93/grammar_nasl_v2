#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(14196);
 script_version ("$Revision: 1.11 $");

 script_cve_id("CVE-2004-0696");
 script_bugtraq_id(10721);
 script_osvdb_id(7795);
 script_xref(name:"Secunia", value:"12063");
 
 script_name(english:"4D WebStar Arbitrary Multiple Vulnerabilities");
 script_summary(english:"Checks for 4D WebStar");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is susceptible to multiple attacks.");

 script_set_attribute(attribute:"description", value:
"The remote server is running a version  of 4D  WebStar Web Server
earlier than 5.3.3. Such versions are reportedly affected by
multiple issues :

  - An attacker may be able to obtain the listing of a
    directory by appending a star (*) to the directory name.

  - An attacker may obtain the file php.ini by requesting
    /cgi-bin/php.ini." );

 script_set_attribute(attribute:"see_also", value:
"http://seclists.org/vulnwatch/2004/q3/3");

 script_set_attribute(attribute:"solution", value:
"Upgrade to 4D WebStar 5.3.3 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/07/13");
 script_cvs_date("$Date: 2016/11/15 13:39:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("ftp_func.inc");


# 4D runs both FTP and WWW on the same port
port = get_http_port(default:80, embedded: 1);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
# Server: 4D_WebSTAR_S/5.3.3 (MacOS X)
if ( "4D_WebSTAR" >< banner &&
     egrep(pattern:"^Server: 4D_WebSTAR.*/([0-4]\.|5\.([0-2]\.|3\.[0-2][^0-9]))", string:banner) ) 
{
 r = http_send_recv3(method: "GET", item:"/cgi-bin/php.ini", port:port);
 if (isnull(r)) exit(0);
 if ( "safe_mode" >< r[2] || "http://php.net/manual/" >< r[2] )
security_warning(port);
}
