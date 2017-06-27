#
# (C) Tenable Network Security, Inc.
#

# References:
#
# Date:	 Mon, 14 Oct 2002 14:50:02 -0400 (EDT)
# From:	"Larry W. Cashdollar" <lwc@vapid.ath.cx>
# To:	bugtraq@securityfocus.com
# Subject: TheServer log file access password in cleartext w/vendor resolution.
#

include("compat.inc");

if (description)
{
 script_id(11914);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2015/06/23 19:16:51 $");

 script_cve_id("CVE-2002-2389");
 script_bugtraq_id(5250);
 script_osvdb_id(57702);

 script_name(english:"TheServer server.ini Direct Request Plaintext Credentials Disclosure");
 script_summary(english:"TheServer stores plaintext passwords in server.ini");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by an information
disclosure vulnerability.");
 script_set_attribute(attribute:"description", value:
"We were able to read the server.ini file. It may contain sensitive
information like plaintext passwords. This flaw is known to affect
TheServer.");
 script_set_attribute(attribute:"solution", value:
"Upgrade your software or reconfigure it to restrict access to
server.ini.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(255);

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/10/29");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "httpver.nasl", "http_version.nasl", "no404.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

function testfile(port, no404, f)
{
  local_var res ;
  res = http_send_recv3(method:"GET", item:f, port:port);
  if (isnull(res)) exit(1, "The web server failed to respond.");

  if (res[0] =~ '^HTTP/[0-9.]+ +2[0-9][0-9]' && res[2])
  {
    if (! no404 || no404 >!< res[2])
      return 1;
  }
  return 0;
#if (egrep(string: b, pattern: "^ *password *=")) ...
}

port = get_http_port(default:80);
no404 = get_kb_item("www/no404/" + port);
if ( no404 ) exit(0);

if (testfile(port: port, no404: no404, f: "/" + rand_str() + ".ini"))
  exit(0);

if (testfile(port: port, no404: no404, f: "/server.ini"))
  security_warning(port);

