#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18293);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2005-1642");
  script_bugtraq_id(13643);
  script_osvdb_id(16575);

  script_name(english:"Woltlab Burning Board verify_email Function SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"The version of Burning Board or Burning Board Lite installed on the
remote host suffers from a SQL injection vulnerability in the way it
verifies email addresses when, for example, a user registers.  An
attacker can exploit this flaw to affect database queries." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00075-05162005" );
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for a patch." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/17");
 script_cvs_date("$Date: 2011/03/12 01:05:14 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Checks for verify_email SQL injection vulnerability in Burning Board");
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_dependencies("burning_board_detect.nasl", "smtp_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, php: 1);


# Test any installs.
wbb = get_kb_list(string("www/", port, "/burning_board"));
wbblite = get_kb_list(string("www/", port, "/burning_board_lite"));
if (isnull(wbb)) {
  if (isnull(wbblite)) exit(0);
  else installs = make_list(wbblite);
}
else if (isnull(wbblite)) {
  if (isnull(wbb)) exit(0);
  else installs = make_list(wbb);
}
else {
  kb1 = get_kb_list(string("www/", port, "/burning_board"));
  kb2 = get_kb_list(string("www/", port, "/burning_board_lite"));
  if ( isnull(kb1) ) kb1 = make_list();
  else kb1 = make_list(kb1);
  if ( isnull(kb2) ) kb1 = make_list();
  else kb2 = make_list(kb2);
  installs = make_list( kb1, kb2 );
}
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    dir = matches[2];

    # Try to exploit it.
    #
    # nb: the actual user name isn't important - registration will 
    #     always fail since we're botching the passwords.
    user = SCRIPT_NAME;
    email = string(get_kb_item("SMTP/headers/From"), "'%20OR%20nessus");

    postdata = string(
      "r_username=", user, "&",
      "r_email=", email, "&",
      "r_password=x&",
      "r_confirmpassword=y&",
      "send=send&",
      "sid=265da345649b38a9dca833e8478f76e5&",
      "disclaimer=viewed"
    );
    r = http_send_recv3(method: 'POST', item: dir+"/register.php", port: port, 
add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
exit_on_fail: 1, version: 11, data: postdata);

    # There's a problem if we get a syntax error.
    if (egrep(pattern: "b>SQL-DATABASE ERROR</b>.+ SELECT COUNT\(\*\) FROM .*_users WHERE email =", string: r[2]) ) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
