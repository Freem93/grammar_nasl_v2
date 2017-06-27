#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18155);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2005-1448");
  script_bugtraq_id(13411);
  script_osvdb_id(15876);

  script_name(english:"Serendipity BBCode Plugin XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is vulnerable to
cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of Serendipity installed on the
remote host does not properly filter user-supplied input for selected
fields if the BBCode plugin is enabled - it is not by default.  By
exploiting this flaw, an attacker can cause arbitrary HTML and script
code to be executed by a user's browser in the context of the affected
website whenever users view malicious entries or comments that the
attacker creates." );
 script_set_attribute(attribute:"see_also", value:"http://www.s9y.org/63.html#A9" );
 script_set_attribute(attribute:"solution", value:
"Disable the BBCode plugin or upgrade to Serendipity 0.8 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/26");
 script_cvs_date("$Date: 2015/01/15 03:38:17 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:s9y:serendipity");
script_end_attributes();

 
  summary["english"] = "Checks for cross-site scripting vulnerabilities in Serendipity BBCode plugin";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("serendipity_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/serendipity");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/serendipity"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # nb: version 0.8 fixes the flaw.
  if (ver =~ "0\.([0-7]|8-beta)")
  {
   security_note(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
