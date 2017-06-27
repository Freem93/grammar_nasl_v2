#
# (C) Tenable Network Security, Inc.
#

#
# Ref:
#  Date: Tue, 8 Jun 2004 13:41:11 +0200 (CEST)
#  From: Fernando Sanchez <fer@ceu.fi.udc.es>
#  To: bugtraq@securityfocus.com
#  Subject: U.S. Robotics Broadband Router 8003 admin password visible



include("compat.inc");

if(description)
{
 script_id(12272);
 script_version("$Revision: 1.13 $");
 script_bugtraq_id(10490);
 script_osvdb_id(53371);

 script_name(english:"US Robotics Broadband Router 8003 menu.htm Admin Password Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure issue." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be a US Robotics Broadband router. 

The device's administrator password is stored as plaintext in a
JavaScript function in the file '/menu.htm', which can be viewed by
anyone." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Jun/116");
 script_set_attribute(attribute:"solution", value:
"Disable the webserver or filter the traffic to the web server via an 
upstream firewall." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/06/11");
 script_cvs_date("$Date: 2016/11/03 14:16:36 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_summary(english:"US Robotics Password Check");

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


# start check

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 1);

r = http_send_recv3(item:"/menu.htm", port:port, method:"GET");
if (isnull(r)) exit(0);
res = r[2];

if (
  "function submitF" >< res &&
  "loginflag =" >< res &&
  "loginIP = " >< res &&
  "pwd = " >< res 
) {
  security_hole(port);
  set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
}

