#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(17194);
  script_version("$Revision: 1.16 $");
  script_cve_id("CVE-2005-0512");
  script_bugtraq_id(12608);
  script_osvdb_id(14021);

  script_name(english:"Mambo Open Source Tar.php Remote File Inclusion");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a remote
file include flaw." );
 script_set_attribute(attribute:"description", value:
"The version of Mambo Open Source on the remote host fails to properly
sanitize input passed through the 'mosConfig_absolute_path' parameter
of the 'Tar.php' script.  Provided PHP's 'register_globals' setting is
enabled, a remote attacker may exploit this vulnerability to cause
code to be executed in the context of the user running the web service
or to read arbitrary files on the target." );
 # http://web.archive.org/web/20050404065812/http://forum.mamboserver.com/showthread.php?t=32119
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?faf6fdd4" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mambo Open Source 4.5.2.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/16");
 script_cvs_date("$Date: 2013/12/23 22:44:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Detect Tar.php Remote File Include Vulnerability in Mambo Open Source");
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
  script_dependencies("mambo_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/mambo_mos");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP");

# Test an install.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/includes/Archive/Tar.php?",
      "mosConfig_absolute_path=../../CHANGELOG%00"
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  if ("Mambo is Free Software" >< res) security_warning(port);
}
