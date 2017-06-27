#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(16336);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/05/21 18:40:21 $");

  script_cve_id("CVE-2005-0345");
  script_bugtraq_id(12482);
  script_osvdb_id(13380, 13920);

  script_name(english:"PHP-Fusion < 5.00 viewthread.php Arbitrary Message Thread / Forum Access");
  script_summary(english:"Checks the version of PHP-Fusion");
  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP script that is affected by an
information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability exists in the version of PHP-Fusion installed on the
remote host that may allow an attacker to read the contents of
arbitrary forums and threads, regardless of the attacker's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/389733" );
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP-Fusion 5.00 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/09");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php_fusion:php_fusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");

  script_dependencies("php_fusion_detect.nasl");
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

if (ereg(pattern:"^([0-4][.,])", string:version))
{
  security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "PHP-Fusion", build_url(qs:dir, port:port), version);
