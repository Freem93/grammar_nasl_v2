#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(42872);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2016/11/23 20:42:24 $");

 script_name(english:"CGI Generic Local File Inclusion (2nd pass)");
 script_summary(english:"Find file inclusions triggered by other attacks");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on this server.");
 script_set_attribute(attribute:"description", value:
"The remote web server hosts CGI scripts that fail to adequately
sanitize request strings.  By leveraging this issue, an attacker may
be able to include a local file and disclose its contents, or even
execute arbitrary code on the remote host.");
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Remote_File_Inclusion");
 script_set_attribute(attribute:"solution", value:
"Restrict access to the vulnerable application. Contact the vendor
for a patch or upgrade.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cwe_id(
  73,  # External Control of File Name or Path
  78,  # Improper Neutralization of Special Elements used in an OS Command 'OS Command Injection'
  98,  # Improper Control of Filename for Include/Require Statement in PHP Program 'PHP File Inclusion'
  473, # PHP External Variable Modification
  632, # Weaknesses that Affect Files or Directories
  714, # OWASP Top Ten 2007 Category A3 - Malicious File Execution
  727,  # OWASP Top Ten 2004 Category A6 - Injection Flaws
  928, # Weaknesses in OWASP Top Ten 2013
  929  # OWASP Top Ten 2013 Category A1 - Injection
 );

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/19");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_END);
 script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl", "torture_cgi_load_estimation1.nasl");
 script_require_ports("Services/www");
 script_require_keys("Settings/enable_web_app_tests");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi.inc");

####

global_var	global_patterns;

# If attacks are added to torture_cgi_cross_site_scripting.nasl, change
# this variable
f = '(alert.[1-4]?[0-9][0-9].|foobar)';

i = 0;
global_patterns[i++] = 'RE:Warning: [a-z_]+\\(/.+' + f + '\\): failed to open stream: (Permission denied|No such file or directory) in /.+ on line [0-9]';
global_patterns[i++] = 'RE:Fatal error: [a-z_]+\\(\\): Failed opening required \'/.+/.{0,128}' + f + '.+\' \\(include_path=\'.{0,128}:.{0,128}\'\\) in /.{0,256} on line [0-9]';
global_patterns[i++] = 'RE:form action="\\?lang=.{0,128}'+ f + '.{0,128}\\\\0&char=';
global_patterns[i++] = 'RE:' + f + '.{0,128}\\): failed to open stream: No such file';
global_patterns[i++] = 'RE:' + f + '.{0,128}\\) \\[function.include\\]: failed to open stream: No such file';
global_patterns[i++] = 'RE:' + f + '.{0,128}\\) \\[<a href=\'function.include\'>function.include</a>\\]: failed to open stream: No such file';
global_patterns[i++] = 'RE:' + f + '.{0,128}\\) \\[function.include\\]: failed to open stream: Operation not permitted';
global_patterns[i++] = 'RE:' + f + '.{0,128}\\) \\[<a href=\'function.include\'>function.include</a>\\]: failed to open stream: Operation not permitted';
global_patterns[i++] = 'RE:open_basedir restriction in effect. File\\(.{0,128}' + f;

port = get_kb_item("Services/www");
if (! port) exit(0, 'No web server was detected.');

report = "";
resp_l = get_kb_list("www/"+port+"/cgi_*/response/*");
if (isnull(resp_l)) exit(0, 'No www/'+port+'/cgi_*/response/* KB entry.');

foreach k (keys(resp_l))
{
  v = eregmatch(string: k, pattern: "/cgi_([A-Z][A-Z])/response/([0-9]+)");
  if (isnull(v)) continue;
  code = v[1]; nb = v[2];
  # Already known as a file inclusion?
  if (code == "WL" || code == "WR")
    continue;

  r = get_kb_blob("www/"+port+"/cgi_"+code+"/response/"+nb);
  if (isnull(r))
    r = decode_kb_blob(value: resp_l[k]);

  txt = extract_pattern_from_resp(string: r, pattern: "GL");
  if (strlen(txt))
  {
    req = get_kb_blob("www/"+port+"/cgi_"+code+"/request/"+nb);
    if (! req) continue;
    report = strcat(report, '-------- request --------\n',
   req,
   '------------------------\n\n-------- output --------\n',
   txt, '------------------------\n\n');
  }
}

if (strlen(report) > 0)
{
  security_warning(port:port, extra: report);
}
