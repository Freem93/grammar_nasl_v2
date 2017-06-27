#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(17305);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2005-0741", "CVE-2005-0785");
  script_bugtraq_id(12756);
  script_xref(name:"OSVDB", value:"14827");

  script_name(english:"YaBB YaBB.pl usersrecentposts Action username Parameter XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that is prone to 
cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The installed version of YaBB (Yet Another Bulletin Board) on the
remote host suffers from a remote cross-site scripting flaw due to its
failure to properly sanitize input passed via the 'username' parameter
and used as part of the 'usersrecentposts' action.  By exploiting this
flaw, a remote attacker can cause arbitrary code to be executed in a
user's browser in the context of the affected website, resulting in
the theft of authentication data or other such attacks." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to YaBB version 2 RC2 or greater." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/13");
 script_cvs_date("$Date: 2015/01/16 03:36:09 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Checks for usersrecentposts cross-site scripting vulnerability in YaBB");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses : XSS");
  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

if (thorough_tests) dirs = list_uniq(make_list("/yabb", "/yabb2", "/forum", cgi_dirs()));
else dirs = make_list(cgi_dirs());

test_cgi_xss(port: port, cgi: "/YaBB.pl", dirs: dirs, 
  qs: "<IFRAME%20SRC%3Djavascript:alert('Nessus%2Dwas%2Dhere')><%252FIFRAME>",
  pass_str: "<IFRAME SRC=javascript:alert('Nessus%2Dwas%2Dhere')" );

