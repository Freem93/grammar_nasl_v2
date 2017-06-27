#
# (C) Tenable Network Security, Inc.
#

# Note that we need to be authenticated for this check
# to work properly.
#

include("compat.inc");

if(description)
{
  script_id(11663);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/10/27 15:03:53 $");

  script_cve_id("CVE-2003-0317");
  script_bugtraq_id(7661);
  script_osvdb_id(3183);
  script_xref(name:"Secunia", value:"8850");
  script_xref(name:"EDB-ID", value:"22631");

  script_name(english:"iisPROTECT Encoded URL Authentication Bypass");
  script_summary(english:"Determines if iisprotect can be escaped.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by an
authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running iisPROTECT, an IIS add-on to protect pages
served by the web server. iisPROTECT is affected by an authentication
bypass vulnerability due to a failure to recognize basic URL encoding.
A remote attacher can exploit this, via hex-encoding requested URLs,
to read sensitive files or directories.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/vulnwatch/2003/q2/82");
  script_set_attribute(attribute:"solution", value:
"Upgrade to iisPROTECT version 2.2.0.9.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2003/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:iisprotect:iisprotect");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

  script_dependencies("no404.nasl", "http_version.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

# Check starts here
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if (report_paranoia < 2)
{
  server_name = http_server_header(port:port);
  if (isnull(server_name))
    audit(AUDIT_WEB_BANNER_NOT, port);
  if ("iis/" >!< tolower(server_name))
    audit(AUDIT_WRONG_WEB_SERVER, port, "IIS");
}

no404 = get_kb_item("www/no404/"+port);
if (strlen(no404) > 0)
{
  if (report_paranoia < 1 || no404 == "HTTP")
    exit(1, "The web server on port "+port+" does not return 404 codes.");
}

function encode(dir)
{
  local_var enc, i;
  for(i=strlen(dir) - 2;i>1;i--)
  {
    if(dir[i] == "/")break;
  }
  if(i <= 1)return NULL;

  enc = "%" + hex(ord(dir[i+1])) - "0x";
  dir = insstr(dir, enc, i+1, i+1);
  return dir;
}
function check(loc)
{
  local_var w, res;
  disable_cookiejar();
  w = http_send_recv3(method:"GET", item:loc, port:port, exit_on_fail:TRUE);

  if (no404)
  {
    res = w[0] + w[1] + w[2];
    if (no404 >< res) return NULL;
  }
  res = w[0];
  enable_cookiejar();
  return res;
}

dirs = get_kb_list("www/"+port+"/content/auth_required");
if(!isnull(dirs)) dirs = make_list(dirs, "/iisprotect/sample/protected");
else dirs = make_list("/iisprotect/sample/protected");

foreach dir (dirs)
{
  resp_code = check(loc:dir);
  if (resp_code =~ "^HTTP/[0-9]\.[0-9] 40[13] ")
  {
    origdir = dir;
    orig_resp = resp_code;
    dir = encode(dir:dir);
    if (empty_or_null(dir))
      exit(0, "Unable to Hex encode the directory name");
    resp_code =  check(loc:dir);
    if(resp_code =~ "^HTTP/[0-9]\.[0-9] 200 ")
    {
      report =
        '\nNessus was able to verify this issue by sending the following'+
        '\nrequests :\n'+
        '\n' + build_url(qs:origdir, port:port) +
        '\nResponse code : ' + orig_resp +
        '\n' + build_url(qs:dir, port:port) +
        '\nResponse code : ' + resp_code +
        '\n';
      security_hole(port:port, extra:report);
      exit(0);
    }
  }
}
audit(AUDIT_WRONG_WEB_SERVER, port, "affected");
