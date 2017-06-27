#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18131);
  script_version("$Revision: 1.17 $");

  script_bugtraq_id(13364);
  script_osvdb_id(15768);

  script_name(english:"Horde Chora common-footer.inc Page Title XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"According to its version, the remote installation of Chora fails to
fully sanitize user-supplied input when setting the parent frame's
page title by JavaScript in 'templates/common-footer.inc'.  By
leveraging this flaw, an attacker may be able to inject arbitrary HTML
and script code into a user's browser to be executed in the context of
the affected website, thereby resulting in the theft of session
cookies and similar attacks." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Chora 1.2.3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/22");
 script_cvs_date("$Date: 2015/01/13 20:37:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:horde:chora");
script_end_attributes();

 
  script_summary(english:"Checks for cross-site scripting vulnerability in Chora common-footer.inc");
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
  script_dependencies("chora_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/chora");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/chora"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (ver =~ "^(0|1\.([01]|2$|2\.[0-2]([^0-9]|$)))")
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
