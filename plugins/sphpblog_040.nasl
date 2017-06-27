#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19516);
  script_version("$Revision: 1.23 $");

  script_cve_id("CVE-2005-2733", "CVE-2005-2787");
  script_bugtraq_id(14667, 14681);
  script_osvdb_id(19012, 19070);

  name["english"] = "Simple PHP Blog <= 0.4.0 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The version of Simple PHP Blog installed on the remote host allows
authenticated attackers to upload files containing arbitrary code to
be executed with the privileges of the web server userid. 

In addition, it likely lets anyone retrieve its configuration file as
well as the user list and to delete arbitrary files subject to the
privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Aug/882");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Aug/996");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48f3599b" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Simple PHP Blog 0.4.5 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Simple PHP Blog Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/25");
 script_cvs_date("$Date: 2016/11/03 21:08:35 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in Simple PHP Blog <= 0.4.0";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("sphpblog_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0, php: 1);

# Test an install.
install = get_kb_item(string("www/", port, "/sphpblog"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  ver = matches[1];
  dir = matches[2];

  # Get the blog's title.
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  title = "";
  pat = "<title>(.+)</title>";
  matches = egrep(string:res, pattern:pat);
  if (matches) {
    foreach match (split(matches, keep:FALSE)) {
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) {
        title = title[1];
        break;
      }
    }
  }

  # Check whether the title is stored as the first field of config.txt.
  if (!isnull(title)) {
    w = http_send_recv3(method:"GET", item:string(dir, "/config.txt"), port:port, exit_on_fail: 1);
    res = w[2];
    # There's a problem if the first field is the title.
    if (egrep(string:res, pattern:string("^", title, "|"))) {
      security_hole(port);
      exit(0);
    }
  }

  # If that didn't work, check the version number.
  if (ver && ver =~ "^0\.([0-3]|4\.0)") {
    report = string(
      "\n",
      "Note that Nessus has determined the vulnerabilities exist on the\n",
      "remote host simply by looking at the version number of Simple\n",
      "PHP Blog installed there.\n"
    );
    security_hole(port:port, extra:report);
    exit(0);
  }
}
