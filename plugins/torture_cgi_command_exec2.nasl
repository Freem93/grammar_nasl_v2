#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(44967);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2017/01/05 15:28:31 $");

 script_name(english:"CGI Generic Command Execution (time-based)");


 script_set_attribute(attribute:"synopsis", value:
"It may be possible to run arbitrary code on the remote web server.");
 script_set_attribute(attribute:"description", value:
"The remote web server hosts CGI scripts that fail to adequately
sanitize request strings.  By leveraging this issue, an attacker may
be able to execute arbitrary commands on the remote host.

Note that this script uses a time-based detection method which is less
reliable than the basic method.");
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Code_injection");
 script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/OS-Commanding");
 script_set_attribute(attribute:"solution", value:
"Restrict access to the vulnerable application. Contact the
vendor for a patch or upgrade.");
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
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/19");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Tortures the arguments of the remote CGIs (command execution, time based)");
 script_category(ACT_MIXED_ATTACK);	# Run later
 script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl", "os_fingerprint.nasl", "torture_cgi_load_estimation1.nasl");
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

unix = 0; win = 0;
if (! get_kb_item("Settings/PCI_DSS") && report_paranoia > 1)
{
  # Even if the web server is based on Unix (for example), it may call a
  # back-end which runs on Windows.
  unix = 1; win = 1;
}
else
{
  os = get_kb_item("Host/OS");
  if (! os)
  {
    debug_print('Unknown OS - enabling all attacks\n');
    unix = 1; win = 1;
  }
  else
  {
    if ("Windows" >< os) win = 1;
    if (egrep(string: os, pattern: "BSD|Linux|Unix|AIX|HP-UX|Mac OS X", icase: 1)) unix = 1;
  }
}

if (! unix && ! win)
{
  debug_print("No attack for OS ", os);
  exit(0, "Will not attack OS "+os);
}

####

# %7C = |	%26 = &		%3B = ;

i = 0;
if (unix)
{
 poison[i++] = " ; x %7C%7C sleep DeLaY %26";
 poison[i++] = "%7C%7C sleep DeLaY %26";
}

# ping -n xxx is not dangerous under Linux
if (win)
{
 poison[i++] = "%26 ping -n DeLaY 127.0.0.1 %26";
 poison[i++] = "x %7C%7C ping -n DeLaY 127.0.0.1 %26";
 poison[i++] = "%7C%7C ping -n DeLaY 127.0.0.1 %26";
 poison[i++] = "%7C ping -n DeLaY 127.0.0.1 %7C";
}

port = torture_cgi_init(vul:'ET');

torture_cgi_delay(port: port, vul: "ET");
