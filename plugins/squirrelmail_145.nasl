#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18504);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2005-1769", "CVE-2005-2095");
  script_bugtraq_id(13973, 14254);
  script_osvdb_id(17360, 17361, 17873, 17874);
 
  name["english"] = "SquirrelMail < 1.45 Multiple Vulnerabilities";
  script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of SquirrelMail installed on the
remote host is prone to multiple flaws :

  - Post Variable Handling Vulnerabilities
    Using specially crafted POST requests, an attacker may
    be able to set random variables in the file
    'options_identities.php', which could lead to accessing
    other users' preferences, cross-site scripting attacks,
    and writing to arbitrary files.

  - Multiple Cross-Site Scripting Vulnerabilities
    Using a specially crafted URL or email message, an 
    attacker may be able to exploit these flaws, stealing 
    cookie-based session identifiers and thereby hijacking
    SquirrelMail sessions." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74e2c299" );
 script_set_attribute(attribute:"see_also", value:"http://www.squirrelmail.org/security/issue/2005-06-15" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/405202" );
 script_set_attribute(attribute:"see_also", value:"http://www.squirrelmail.org/security/issue/2005-07-13" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SquirrelMail 1.45 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/06/15");
 script_cvs_date("$Date: 2016/05/12 14:55:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:squirrelmail:squirrelmail");
script_end_attributes();


  summary["english"] = "Checks for multiple vulnerabilities in SquirrelMail < 1.45";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("squirrelmail_detect.nasl");
  script_require_keys("www/squirrelmail");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/squirrelmail"));
if (isnull(install)) exit(1);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # There's a problem if the version is < 1.45.
  if (ver =~ "^1\.([0-3]\.|4\.[0-4]([^0-9]|$))") {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
