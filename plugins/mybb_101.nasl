#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20373);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/05/22 19:48:53 $");

  script_cve_id("CVE-2005-4602");
  script_bugtraq_id(16082, 16097);
  script_osvdb_id(22159);

  script_name(english:"MyBB < 1.01 function_upload.php SQLi");
  script_summary(english:"Checks for SQL injection vulnerabilities in MyBB < 1.01.");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MyBB installed on the remote host is affected by a SQL
injection vulnerability due to improper sanitization of user-supplied
input to the to the file extension of an uploaded file. A remote,
unauthenticated attacker can exploit this issue to manipulate SQL
queries, resulting in the disclosure of sensitive information and
modification of data.

Note that the application is reportedly affected by an additional SQL
injection vulnerability. However, Nessus has not tested for the
additional issue.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/420573");
  script_set_attribute(attribute:"see_also", value:"http://community.mybboard.net/showthread.php?tid=5633");
  script_set_attribute(attribute:"solution", value:"Upgrade to MyBB version 1.01 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mybb:mybb");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("mybb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "installed_sw/MyBB");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "MyBB";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

# Try to exploit flaw in the cookie to generate a syntax error.
magic = rand_str(length:8);
r = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + "/admin/global.php?action=" + SCRIPT_NAME, 
  add_headers  : make_array("Cookie", "mybbadmin='"+magic),
  exit_on_fail : TRUE
);

# There's a problem if we get a syntax error involving the word "nessus".
#
# nb: the code splits the cookie on "_" so we can't just use our script 
#     name as we usually do.
if (egrep(pattern:"an error in your SQL syntax.+ WHERE uid=''" + magic, string: r[2]))
{
  output = strstr(r[2], "an error in your SQL syntax");
  if (empty_or_null(output)) output = r[2];

  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    generic    : TRUE,
    sqli       : TRUE,  # Sets SQLInjection KB key
    request    : make_list(http_last_sent_request()),
    output     : chomp(output)
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
