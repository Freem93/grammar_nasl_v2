#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(18212);
 script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2016/09/22 15:18:21 $");
 
 script_cve_id("CVE-2005-1507");
 script_bugtraq_id(13538, 14192);
 script_osvdb_id(16154);

 script_name(english:"4D WebSTAR Tomcat Plugin Remote Buffer Overflow");
 script_summary(english:"Checks for 4D WebSTAR");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is susceptible to a remote buffer overflow
attack." );
 script_set_attribute(attribute:"description", value:
"The remote server is running 4D WebSTAR Web Server. 

According to its banner, the remote version of 4D WebSTAR has a buffer
overflow in its Web Server Tomcat plugin, included and activated by
default.  By sending a malicious packet, an attacker may be able to
crash the affected service or possibly execute arbitrary code on the
affected host, although that appears to be improbable." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/May/85");
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/06");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("ftp_func.inc");


# 4D runs both FTP and WWW on the same port
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
# Server: 4D_WebSTAR_S/5.3.3 (MacOS X)
if ( "4D_WebSTAR" >< banner &&
     egrep(pattern:"^Server: 4D_WebSTAR.*/([0-4]\.|5\.([0-2]\.|3\.|4[^.]))", string:banner) ) security_warning(port);
