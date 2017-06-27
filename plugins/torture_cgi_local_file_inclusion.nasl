#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(42056);
 script_version ("$Revision: 1.13 $");

 script_name(english: "CGI Generic Local File Inclusion");
 script_summary(english: "Tortures the arguments of the remote CGIs (local file inclusion)");
 
 script_set_attribute(attribute:"synopsis", value:
"Confidential data may be disclosed on this server." );
 script_set_attribute(attribute:"description", value:
"The remote web server hosts CGI scripts that fail to adequately sanitize 
request strings.  By leveraging this issue, an attacker may be able 
to include a local file and disclose its content." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Remote_File_Inclusion" );
 script_set_attribute(attribute:"solution", value:
"Restrict access to the vulnerable application. Contact the vendor 
for a patch or upgrade." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_cwe_id(
  73, # External Control of File Name or Path
  78, # Improper Neutralization of Special Elements used in an OS Command 'OS Command Injection'
  98, # Improper Control of Filename for Include/Require Statement in PHP Program 'PHP File Inclusion'
  473,  # PHP External Variable Modification
  632,  # Weaknesses that Affect Files or Directories
  714,  # OWASP Top Ten 2007 Category A3 - Malicious File Execution
  727, # OWASP Top Ten 2004 Category A6 - Injection Flaws
  928, # Weaknesses in OWASP Top Ten 2013
  929  # OWASP Top Ten 2013 Category A1 - Injection
 );
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/07");
 script_cvs_date("$Date: 2017/01/05 15:28:31 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 # Not dangerous, but we want to give it a chance to run after the directory traversal and remote injection checks
 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl", "torture_cgi_load_estimation1.nasl");
 script_require_ports("Services/www", 80);
 script_timeout(43200);	# Timeout is managed by the script itself
 script_require_keys("Settings/enable_web_app_tests");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi.inc");

function torture_cgi_response_post_check(resp) { return 0; }	# stub

####

i = 0; 

## Check that the interpretor are working ##
exclcgi = NULL;
srcRE = 'RE:';

if (broken_php_interpretor(port: port, vul: "WL"))
  exclcgi += '|\\.php[3-5]?$';
else
  srcRE += '<\\?php|';

if (broken_asp_interpretor(port: port, vul: "WL"))
  exclcgi += '|\\.aspx?$';
else
  srcRE += '<%@ +LANGUAGE=.* %>|';

srcRE += 'use +CGI|\\.CreateObject *\\ *\\( *"';
if (exclcgi) exclcgi = substr(exclcgi, 1);

########

flaws_and_patterns = make_array(
"FILENAME",	srcRE
); 

if (thorough_tests)
  foreach k (make_list("FILENAME%00.html", "FILENAME%00.jpg","FILENAME/."))
     flaws_and_patterns[k] = srcRE;


FP_pattern = "RE:<!-- +<\?php .*\?> *-->";

port = torture_cgi_init(vul:'WL');


report = torture_cgis(port: port, vul: "WL", exclude_cgi: exclcgi);

if (strlen(report) > 0)
{
  security_warning(port:port, extra: report);
}
