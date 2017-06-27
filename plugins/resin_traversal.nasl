#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10656);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2016/05/16 14:22:07 $");

 script_cve_id("CVE-2001-0304");
 script_bugtraq_id(2384);
 script_osvdb_id(544);

 script_name(english:"Resin Traversal Arbitrary File Access");
 script_summary(english:"request \..\..\file.txt");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a directory traversal attack.");
 script_set_attribute(attribute:"description", value:
"It is possible to read arbitrary files on the remote server by
prepending /\../\../ to the file name.");
 script_set_attribute(attribute:"solution", value:
"Upgrade to Resin version 1.2.3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/02/15");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/04/17");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:caucho:resin");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8080);
 script_require_keys("www/resin");

 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080); # by default, Resin listens on this port, not 80

# Unless we're paranoid, make sure the banner is from Resin.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner) exit(1, "Unable to get the banner from web server on port "+port+".");
  if ("Resin" >!< banner) exit(1, "The web server on port "+port+" does not appear to be Resin.");
}

r = http_send_recv3(method: "GET", port: port, item: '/\\../readme.txt');
if ("This is the README file for Resin(tm)" >< r[0]+r[1]+r[2])
   security_warning(port);

