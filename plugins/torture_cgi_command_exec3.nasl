#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(51528);
 script_version ("$Revision: 1.9 $");
 script_cvs_date("$Date: 2017/01/05 15:28:31 $");

 script_name(english: "CGI Generic Command Execution (time-based, intrusive)");
 

 script_set_attribute(attribute:"synopsis", value:
"It may be possible to run arbitrary code on the remote web server.");
 script_set_attribute(attribute:"description", value:
"The remote web server hosts CGI scripts that seem to fail to
adequately sanitize request strings.  By leveraging this issue, an
attacker may be able to execute arbitrary commands on the remote host. 

Note that :

  - This script uses a time-based detection method that is 
    less reliable than the basic method. 

  - The method is intrusive and may lock the web server if 
    the web application is allows Command Injection. If this 
    happens, restart the web server.");
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Code_injection" );
 script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/OS-Commanding");
 script_set_attribute(attribute:"solution", value:
"Restrict access to the affected application and contact the vendor
for a patch or upgrade." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cwe_id(
  20,  # Improper Input Validation
  74,  # Improper Neutralization of Special Elements in Output Used by a Downstream Component 'Injection'
  77,  # Command injection
  78,  # OS Command Injection
  713, # OWASP Top Ten 2007 Category A2 - Injection Flaws
  722, # OWASP Top Ten 2004 Category A1 - Unvalidated Input
  727, # OWASP Top Ten 2004 Category A6 - Injection Flaws
  928, # Weaknesses in OWASP Top Ten 2013
  929  # OWASP Top Ten 2013 Category A1 - Injection
 );
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/14");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english: "Tortures the arguments of the remote CGIs (command execution, time based, intrusive)");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl", "torture_cgi_command_exec2.nasl", "torture_cgi_load_estimation1.nasl");
 script_require_ports("Services/www", 80);
 script_timeout(43200);	# Timeout is managed by the script itself
 script_require_keys("Settings/enable_web_app_tests");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi_delay.inc");
include("url_func.inc");


t0 = get_read_timeout();

####

# %7C = |	%26 = &		%3B = ;

i = 0; 
poison[i++] = "%7C%7C ping -c DeLaY 127.0.0.1 ; x %7C%7C ping -i DeLaY 127.0.0.1 ; x %7C%7C ping -n DeLaY 127.0.0.1 %26";
poison[i++] = "%7C%7C ping -c DeLaY 127.0.0.1 %7C%7C ping -i DeLaY 127.0.0.1 %7C%7C ping -n DeLaY 127.0.0.1 %26";
poison[i++] = "ping -i DeLaY 127.0.0.1 %7C";
poison[i++] = "%26 ping -i DeLaY 127.0.0.1 %26";
poison[i++] = "%0a ping -i DeLaY 127.0.0.1 %0a";
if (experimental_scripts)
{
  poison[i++] = "%3B ping 127.0.0.1 %3B";
  poison[i++] = "; ping 127.0.0.1 ;";
  poison[i++] = "`ping 127.0.0.1`";
}

port = torture_cgi_init(vul:'EI');

torture_cgi_delay(port: port, vul: "EI");
