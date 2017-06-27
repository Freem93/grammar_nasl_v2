#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#
# Changes by Tenable
# - Updated to use compat.inc (11/20/2009)

include("compat.inc");

if (description) {
  script_id(16228);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-0075", "CVE-2005-0103", "CVE-2005-0104");
  script_bugtraq_id(12337);
  script_osvdb_id(13145, 13146, 13147);
 
  script_name(english:"SquirrelMail < 1.4.4 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has a PHP script that is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The target is running at least one instance of SquirrelMail whose
version number suggests it is affected by one or more cross-site
scripting vulnerabilities :

- Insufficient escaping of integer variables in webmail.php allows a
remote attacker to include HTML / script into a SquirrelMail webpage
(affects 1.4.0-RC1 - 1.4.4-RC1). 

- Insufficient checking of incoming URL vars in webmail.php allows an
attacker to include arbitrary remote web pages in the SquirrelMail
frameset (affects 1.4.0-RC1 - 1.4.4-RC1). 

- A recent change in prefs.php allows an attacker to provide a
specially crafted URL that could include local code into the
SquirrelMail code if and only if PHP's register_globals setting is
enabled (affects 1.4.3-RC1 - 1.4.4-RC1). 
 
***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number of Squirrelmail 
***** installed there." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SquirrelMail 1.4.4 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/14");
 script_cvs_date("$Date: 2015/02/13 21:07:13 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:squirrelmail:squirrelmail");
script_end_attributes();

 
  summary["english"] = "Checks for Three XSS Vulnerabilities in SquirrelMail < 1.4.4";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 George A. Theall");

  script_family(english:"CGI abuses");

  script_dependencie("global_settings.nasl", "squirrelmail_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/squirrelmail");
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
debug_print("searching for 3 XSS vulnerabilities in SquirrelMail < 1.4.3 on port ", port, ".");


# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/squirrelmail"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    debug_print("checking version ", ver, " under ", dir, ".");

    if (ereg(pattern:"^1\.4\.([0-3](-RC.*)?|4-RC1)$", string:ver)) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}
