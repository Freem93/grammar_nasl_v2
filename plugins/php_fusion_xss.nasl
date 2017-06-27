#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15392);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/01/14 20:12:25 $");

  script_osvdb_id(10348);

  script_name(english:"PHP-Fusion homepage address Parameter XSS");
  script_summary(english:"Checks the version PHP-Fusion");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP script that is prone to
cross-site scripting attacks."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability exists in the version of PHP-Fusion installed on the
remote host that could allow an attacker to perform a cross-site
scripting attack and execute arbitrary HTML and script code in the
context of the user's browser."
  );
  script_set_attribute(attribute:"solution", value:"Apply the patch for 4.01.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php_fusion:php_fusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");

  script_dependencie("php_fusion_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/php_fusion");

  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname      : "php_fusion",
  port         : port,
  exit_on_fail : TRUE
);
dir = install["dir"];
version = install["ver"];

if (ereg(pattern:"^([0-3][.,]|4[.,]0[01]([^0-9]|$))", string:version))
{
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "PHP-Fusion", build_url(qs:dir, port:port), version);
