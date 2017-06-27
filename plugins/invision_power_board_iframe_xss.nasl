#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(17609);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2005-0886");
  script_bugtraq_id(12888);
  script_osvdb_id(16604);

  script_name(english:"Invision Power Board HTTP POST Request IFRAME Tag XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is vulnerable to a
cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The version of Invision Power Board installed on the remote host does
not properly sanitize HTML tags, which enables a remote attacker to
inject a malicious IFRAME when posting a message to one of the hosted
forums.  This could cause arbitrary HTML and script code to be
executed in the context of users browsing the forum, which could allow
an attacker to steal cookies or misrepresent site content." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Invision Power Board 2.0.3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/24");
 script_cvs_date("$Date: 2015/01/14 03:46:11 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:invisionpower:invision_power_board");
script_end_attributes();

  script_summary(english:"Checks for IFRAME HTML Injection Vulnerability in Invision Power Board");
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
  script_dependencies("invision_power_board_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^(1\.|2\.0\.[0-2][^0-9]*)")
  {
   security_note(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
