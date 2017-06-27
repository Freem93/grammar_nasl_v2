#
# This script is (C) Tenable Network Security
#



include("compat.inc");

if(description)
{
 script_id(17209);
 script_cve_id("CVE-2005-0526", "CVE-2005-0630", "CVE-2005-0631");
 script_bugtraq_id(12631, 12633, 12666, 12690, 12694);
 script_osvdb_id(14083, 14084, 14085, 14360, 14367);

 script_version ("$Revision: 1.22 $");
 name["english"] = "PBLang BBS <= 4.65 Multiple Vulnerabilities";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that suffers from
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
PBLang BBS, a bulletin board system written in PHP, that suffers from
the following vulnerabilities:

  - HTML Injection Vulnerability in pmpshow.php.
    An attacker can inject arbitrary HTML and script into the
    body of PMs sent to users allowing for theft of 
    authentication cookies or misrepresentation of the site.

  - Cross-Site Scripting Vulnerability in search.php.
    If an attacker can trick a user into following a specially
    crafted link to search.php from an affected version of
    PBLang, he can inject arbitrary script into the user's 
    browser to, say, steal authentication cookies.

  - Remote PHP Script Injection Vulnerability in ucp.php.
    PBLang allows a user to enter a PHP script into his/her 
    profile values, to be executed with the permissions of
    the web server user whenever the user logs in. 

  - Directory Traversal Vulnerability in sendpm.php.
    A logged-in user can read arbitrary files, subject to
    permissions of the web server user, by passing full
    pathnames through the 'orig' parameter when calling
    sendpm.php.

  - Arbitrary Personal Message Deletion Vulnerability in delpm.php.
    A logged-in user can delete anyone's personal messages by
    passing a PM id through the 'id' parameter and a username 
    through the 'a' parameter when calling delpm.php." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Feb/475" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Feb/476" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Mar/29" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Mar/32" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6808b6a" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PBLang 4.66z or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/02");
 script_cvs_date("$Date: 2016/11/02 14:37:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Checks for multiple vulnerabilities in PBLang BBS <= 4.65";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, php: 1);

function check(loc)
{
  local_var res;

  res = http_get_cache(port:port, item: loc + "/index.php", exit_on_fail: 1);
  if ( 
    "PBLang Project" >< res && 
    egrep(pattern:'<meta name="description" content=".+running with PBLang ([0-3]\\.|4\\.[0-5]|4\\.6[0-5])">', string:res)
  ) { 
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0); 
  }
}

foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
