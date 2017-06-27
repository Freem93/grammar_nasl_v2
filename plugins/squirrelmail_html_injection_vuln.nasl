#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14217);
  script_version("$Revision: 1.22 $");

  script_cve_id("CVE-2004-0639");
  script_bugtraq_id(10450);
  script_osvdb_id(8291, 8292);

  script_name(english:"SquirrelMail < 1.2.11 Multiple Script XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by 
multiple cross-site scripting vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The target is running at least one instance of SquirrelMail whose
version number is between 1.2.0 and 1.2.10 inclusive.  Such versions do
not properly sanitize From headers, leaving users vulnerable to XSS
attacks.  Further, since SquirrelMail displays From headers when listing
a folder, attacks does not require a user to actually open a message,
only view the folder listing.

For example, a remote attacker could effectively launch a DoS against
a user by sending a message with a From header such as :

From:<!--<>(-->John Doe<script>document.cookie='PHPSESSID=xxx; path=/';</script><>

which rewrites the session ID cookie and effectively logs the user
out.

***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number(s) of Squirrelmail
***** installed there." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SquirrelMail 1.2.11 or later or wrap the call to
sqimap_find_displayable_name in printMessageInfo in
functions/mailbox_display.php with a call to htmlentities." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/05/29");
 script_cvs_date("$Date: 2015/01/23 22:03:56 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:squirrelmail:squirrelmail");
script_end_attributes();

 
  summary["english"] = "Check Squirrelmail for HTML injection vulnerability";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");

  script_family(english:"CGI abuses : XSS");

  script_dependencie("squirrelmail_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/squirrelmail");
  exit(0);
}

include("http_func.inc");

host = get_host_name();
port = get_http_port(default:80);

if (!get_port_state(port)) 
	exit(0);

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/squirrelmail"));
if (isnull(installs)) 
	exit(0);

foreach install (installs) 
{
	matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  	if (!isnull(matches)) 
	{
    		ver = matches[1];
    		dir = matches[2];

    		if (ereg(pattern:"^1\.2\.([0-9]|10)$", string:ver)) 
		{
      			security_warning(port);
			set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      			exit(0);
    		}
  	}
}


