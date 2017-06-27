#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(46194);
 script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2017/01/05 15:28:31 $");

 script_name(english:"CGI Generic Path Traversal (write test)");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be modified on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote web server hosts CGI scripts that fail to adequately
sanitize request strings and are affected by directory traversal or
local file inclusion vulnerabilities.

By leveraging this issue, an attacker may be able to modify arbitrary
files on the web server or execute commands.

Due to the way this flaw is tested, this script is prone to false
positives.");
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Directory_traversal");
 script_set_attribute(attribute:"see_also", value:"http://cwe.mitre.org/data/definitions/22.html");

 script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/Path-Traversal");
 script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/Null-Byte-Injection");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?addbae30");

 script_set_attribute(attribute:"solution", value:
"Restrict access to the vulnerable application. Contact the
vendor for a patch or upgrade.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/30");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_xref(name:"OWASP", value:"OWASP-AZ-001");

 script_summary(english:"Tortures the arguments of the remote CGIs (traversal, write test)");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 # torture_cgi_injectable_param.nasl is just needed by the anti-FP
 script_dependencie("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl", "os_fingerprint.nasl", "torture_cgi_injectable_param.nasl", "torture_cgi_load_estimation2.nasl");
 script_require_ports("Services/www", 80);
 # Run in paranoid mode until we find a way to eliminate most FPs
# script_require_keys("Settings/enable_web_app_tests", "Settings/ParanoidReport");
 script_require_keys("Settings/enable_web_app_tests");
 script_timeout(43200);	# Timeout is managed by the script itself
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi_yesno.inc");
include("url_func.inc");

################################


unix = 0; win = 0;
if (!get_kb_item("Settings/PCI_DSS") && (thorough_tests || report_paranoia > 1))
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

i = 0;

if (unix)
{
poison_ok[i] = "../../../../../../../../../../tmp/writetest"+rand()+".txt";
poison_ko[i] = "../../../../../../../../../../tmp";
i ++;


}

if (win)
{
poison_ok[i] = "../../../../../../../../../../writetest"+rand()+".txt";
poison_ko[i] = "../../../../../../../../../../windows/system32/config/sam";
i ++;

}


port = torture_cgi_init(vul:'TW');


# The probability of FPs is quite low with the current code
if (report_paranoia < 1) ei = 1;
else			 ei = 0;

report = torture_cgis_yesno(port: port, vul: "TW", exclude_injectable: ei);
if (strlen(report) > 0)
{
  security_warning(port:port, extra: report);
}
