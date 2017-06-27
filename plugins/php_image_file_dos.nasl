#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(17687);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_cve_id("CVE-2005-0524", "CVE-2005-0525");
  script_bugtraq_id(12962, 12963);
  script_osvdb_id(15183,15184);

  script_name(english:"PHP Multiple Image Processing Functions File Handling DoS");
  script_summary(english:"Checks version of PHP");
 
  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server is prone to denial of service attacks."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of PHP installed on the remote
host is vulnerable to a denial of service attack due to its failure to
properly validate file data in the routines 'php_handle_iff' and
'php_handle_jpeg', which are called by the PHP function
'getimagesize'.  Using a specially crafted image file, an attacker can
trigger an infinite loop when 'getimagesize' is called, perhaps even
remotely in the cases where image uploads are allowed."
  );
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=222
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ad00097");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/394797");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/release_4_3_11.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP 4.3.11 / 5.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/02");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses"); 
 
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

version = php["ver"];
source = php["src"];

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (report_paranoia < 2 && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

if (version =~ "^[0-3]\." ||
    version =~ "^4\.[0-2]\." ||
    version =~ "^4\.3\.([0-9]|10)($|[^0-9])" || 
    version =~ "^5\.0\.[0-3]($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 4.3.11 / 5.0.4\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
