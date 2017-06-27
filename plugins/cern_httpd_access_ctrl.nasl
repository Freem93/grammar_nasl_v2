#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(17230);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2017/03/21 03:23:57 $");

 script_osvdb_id(29234);

 script_name(english:"CERN httpd Double Slash Protected Webpage Bypass");
 script_summary(english:"Determines if web access control can be circumvented");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote web server allows an attacker to access protected web pages
by replacing slashes in the URL with '//' or '/./', which is a known
problem in older versions of CERN web server.");
 script_set_attribute(attribute:"solution", value:
"Contact the web server vendor for an update or tighten its filtering
rules to reject patterns such as :

 //*
 *//*
 /./*
 */./*");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"vuln_publication_date", value:"1997/05/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/28");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("find_service1.nasl", "http_version.nasl", "webmirror.nasl", "no404.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# If this script gives FP, uncomment the next line
if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
no404 = get_kb_item(strcat('www/no404/', port));

function check(port, loc)
{
 local_var	r;
 r = http_send_recv3(method: "GET", item:loc, port:port, exit_on_fail: 1);
 if (r[0] =~ "^HTTP/[0-9]\.[0-9] +40[13]") return 403;
 else if (r[0] =~ "^HTTP/[0-9]\.[0-9] +200 ")
 {
   if (no404 && no404 >< r[1]+r[2]) return 404;
   else return 200;
 }
 else return NULL;
}

dirs = get_kb_list(strcat("www/", port, "/content/auth_required"));
if (isnull(dirs)) exit(0, "No protected page was found on port "+port+".");

foreach dir (dirs)
{
  if (check(port: port, loc: dir) == 403)
  {
    foreach pat (make_list("//", "/./"))
    {
      dir2 = ereg_replace(pattern: "^/", replace: pat, string: dir);
      if (check(port: port, loc: dir2) == 200)
      {
        debug_print('>', dir2, '< can be read on ', get_host_name(),
	':', port, '\n');
        security_warning(port: port);
        exit(0);
      }

      dir2 = ereg_replace(pattern: "^(.+)/", replace: "\\1"+pat, string: dir);
      if (check(port: port, loc: dir2) == 200)
      {
        debug_print('>', dir2, '< can be read on ', get_host_name(),
	':', port, '\n');
        security_warning(port: port);
        exit(0);
      }
    }
  }
}
