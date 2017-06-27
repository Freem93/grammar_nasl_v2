#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21597);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/06/13 20:14:28 $");

  script_cve_id("CVE-2006-2513");
  script_bugtraq_id(18018);
  script_osvdb_id(25575);

  script_name(english:"Sun Server Console Authentication Bypass");
  script_summary(english:"Tries to authenticate to Server Console as admin/admin");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is protected with a default set of credentials.");
  script_set_attribute(attribute:"description", value:
"The remote host is running the Sun ONE Server Console, which provides
an administrative interface to the Sun Java System Directory Server
installed there.

The Server Console instance on the remote host allows authentication
using a default set of credentials - 'admin' / 'admin'.  This is likely
the result not of a deliberate choice during installation but rather a
flaw in the version of Directory Server used for the initial
installation.");
  # http://web.archive.org/web/20070319094319/http://sunsolve.sun.com/search/document.do?assetkey=1-26-102345-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?115f5475");
  script_set_attribute(attribute:"solution", value:
"Manually change the administrative user password as described in the
vendor advisory referenced above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 390);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_http_port(default:390);

# Make sure that it looks like the Server Console and that it's protected.
banner = get_http_banner(port:port);
if (!banner || "Netscape-Enterprise" >!< banner) exit(0, "The web server listening on port "+port+" does not look like Sun ONE.");

url = "/admin-serv/authenticate";
w = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
if ('WWW-authenticate: basic realm="Sun ONE Administration Server"' >!< w[1]) exit(0, "The Sun ONE Administration Server listening on port "+port+" does not require credentials.");


# Try to log in.
w = http_send_recv3(method:"GET", item:url, port:port, username: "admin", password: "admin", exit_on_fail:TRUE);

res = strcat(w[0], w[1], '\r\n', w[2]);

# There's a problem if we get in.
if ("UserDN: cn=admin-serv" >< res) security_hole(port);
else audit(AUDIT_LISTEN_NOT_VULN, "Sun ONE Administration Server", port);
