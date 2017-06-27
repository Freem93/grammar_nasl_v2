#
# (C) Tenable Network Security, Inc.
# 



include("compat.inc");

if (description) {
  script_id(19775);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2005-3078", "CVE-2005-3079");
  script_bugtraq_id(14900, 14904);
  script_osvdb_id(19616, 19617);

  name["english"] = "PunBB < 1.2.8 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains two PHP scripts that may allow
arbitrary code execution, local file disclosure, and cross-site
scripting attacks." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of PunBB installed on the remote
host suffers from several flaws. 

  - A File Include Vulnerability
    The application fails to validate the 'language' 
    parameter when a user updates his profile and uses that 
    throughout the application to require PHP code in order
    to display messages. An attacker with an account on the 
    affected application may be able to exploit this issue to
    read arbitrary files and even to execute local files with 
    arbitrary PHP code subject to the privileges of the web 
    server user id.

  - A Cross-Site Scripting Vulnerability
    The application also does not sanitize input passed to
    the 'email' parameter of the 'login.php' script when
    requesting a new password, which permits cross-site 
    scripting attacks such as theft of authentication 
    cookies." );
 script_set_attribute(attribute:"see_also", value:"http://www.punbb.org/changelogs/1.2.7_to_1.2.8.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PunBB 1.2.8 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/21");
 script_cvs_date("$Date: 2015/02/11 21:07:50 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
  summary["english"] = "Checks for multiple vulnerabilities in PunBB < 1.2.8";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("punBB_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/punBB");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/punBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^(0\.|1\.([01]\.|2\.[0-7]($|[^0-9])))") {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
