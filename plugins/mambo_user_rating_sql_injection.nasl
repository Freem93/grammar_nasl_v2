#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18495);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2005-2002");
  script_bugtraq_id(13966, 14117, 14119);
  script_osvdb_id(17323, 17744, 17745, 17746, 17747, 17748);

  name["english"] = "Mambo Open Source < 4.5.2.3 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The installed version of Mambo Open Source on the remote host suffers
from the following flaws :

  - Session ID Spoofing Vulnerability
    An unspecified flaw in the script 'administrator/index3.php'
    can be exploited to spoof session IDs.

  - Local File Disclosure Vulnerability
    The 'includes/DOMIT/testing_domit.php' script may be used
    to read the contents of local files such as Mambo's
    configuration file, which holds database credentials.

  - A SQL Injection Vulnerability
    The application fails to properly sanitize user-supplied 
    input to the 'user_rating' parameter of the 
    'components/com_content/content.php' script before using 
    it in SQL statements.

  - Multiple Unspecified Injection Vulnerabilities
    Various class 'check' methods fail to properly
    sanitize input, although it's unknown precisely
    what dangers these flaws present." );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2005-June/034575.html" );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/advisories/15710" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mambo version 4.5.2.3 or greater." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/05");
 script_cvs_date("$Date: 2012/12/12 22:50:07 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mambo:mambo");
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in Mambo Open Source < 4.5.2.3";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");

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
if (isnull(install)) exit(0, "Mambo is not installed on port "+port);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the SQL injection flaw.
  #
  # nb: randomize CID to avoid already voted problems.
  cid = rand() % 100;
  w = http_send_recv3(method:"GET", 
    item:string(
      dir, "/index.php?",
      "option=com_content&",
      "task=vote&",
      "id=1&",
      "Itemid=1&",
      "cid=", cid, "&",
      # this just produces a syntax error in a vulnerable version.
      "user_rating=1'", SCRIPT_NAME
    ),
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if we see a syntax error mentioning this plugin.
  if (
    "DB function failed with error number 1064" >< res &&
    string("right syntax to use near '", SCRIPT_NAME, "', '") >< res
  ) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
