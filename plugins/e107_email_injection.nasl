#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21621);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/09/24 21:08:38 $");

  script_cve_id("CVE-2006-2591");
  script_osvdb_id(25740);

  script_name(english:"e107 email.php Arbitrary Mail Relay");
  script_summary(english:"Tries to send arbitrary email with e107");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that can be used to send
arbitrary email messages."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of e107 installed on the remote host contains a script,
'email.php' that allows an unauthenticated user to send email
messages to arbitrary users and to control, to a large degree, the
content of those messages.  This issue can be exploited to send spam
or other types of abuse through the affected system."
  );
  script_set_attribute(attribute:"see_also", value:"http://e107.org/e107_plugins/forum/forum_viewtopic.php?66179");
  script_set_attribute(attribute:"see_also", value:"http://e107.org/comment.php?comment.news.788");
  script_set_attribute(attribute:"solution", value:
"Either remove the affected script or upgrade to e107 version 0.7.5 or
later, which uses a 'captcha' system to minimize automated
exploitation of this issue."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:e107:e107");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("e107_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/e107");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:80, php:TRUE);

# Test an install.
install = get_install_from_kb(appname:'e107', port:port, exit_on_fail:TRUE);

dir = install['dir'];
url = dir + "/email.php?" + SCRIPT_NAME;

# Make sure the affected script exists.
r = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
res = r[2];

# If it does...
if ("name='emailsubmit'" >< res)
{
  # Try to send a message.
  note = "Test message sent by Nessus / " + SCRIPT_NAME + ".";
  postdata = "comment=" + urlencode(str:note) + "&" +
    "author_name=nessus&email_send=nobody@123.zzzz&" +
    "emailsubmit=Send+Email";

  res = http_send_recv3(
    method : "POST",
    item   : url,
    port   : port,
    data   : postdata,
    content_type : "application/x-www-form-urlencoded",
    exit_on_fail : TRUE);

  # There's a problem if the message was sent.
  if (">Email sent<" >< res[2])
  {
    if (report_verbosity > 0)
    {
      report =
        '\nNessus was able to verify the issue exists using the following request :' +
        '\n' +
        '\n' + http_last_sent_request() +
        '\n';
    security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "e107", build_url(qs:dir, port:port));
