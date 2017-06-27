#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(52483);
 script_version("$Revision: 1.10 $");
 script_cvs_date("$Date: 2016/11/23 20:42:24 $");

 script_name(english: "CGI Generic XSS (persistent, 3rd Pass)");
 script_summary(english: "Tortures the arguments of the remote CGIs (persistent XSS)");


 script_set_attribute(attribute:"synopsis", value:
"A CGI application hosted on the remote web server is potentially
prone to cross-site scripting attacks.");
 script_set_attribute(attribute:"description", value:
"The remote web server hosts one or more CGI scripts that fail to
adequately sanitize request strings containing malicious JavaScript. 
By leveraging this issue, an attacker may be able to cause arbitrary
HTML and script code to be executed in a user's browser within the
security context of the affected site. 

This script identified patterns that were injected to test 'reflected'
(aka 'non-persistent') XSS. The issues are likely to be 'persistent' 
(or 'stored') after all." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Cross_site_scripting#Persistent" );
 script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/Cross-Site+Scripting");
 script_set_attribute(attribute:"solution", value:
"Restrict access to the vulnerable application and contact the vendor
for a patch or upgrade." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cwe_id(
  20,  # Improper Input Validation
  74,  # Improper Neutralization of Special Elements in Output Used by a Downstream Component 'Injection'
  79,  # Cross-Site Scripting
  80,  # Improper Neutralization of Script-Related HTML Tags in a Web Page Basic XSS
  81,  # Improper Neutralization of Script in an Error Message Web Page
  83,  # Improper Neutralization of Script in Attributes in a Web Page
  86,  # Improper Neutralization of Invalid Characters in Identifiers in Web Pages
  116, # Improper Encoding or Escaping of Output
  442, # Web problems
  692, # Incomplete Blacklist to Cross-Site Scripting
  712, # OWASP Top Ten 2007 Category A1 - Cross Site Scripting XSS
  722, # OWASP Top Ten 2004 Category A1 - Unvalidated Input
  725, # OWASP Top Ten 2004 Category A4 - Cross-Site Scripting XSS Flaws
  751, # 2009 Top 25 - Insecure Interaction Between Components
  801, # 2010 Top 25 - Insecure Interaction Between Components
  811, # OWASP Top Ten 2010 Category A2 - Cross-Site Scripting XSS
  928, # Weaknesses in OWASP Top Ten 2013
  931  # OWASP Top Ten 2013 Category A3 - Cross-Site Scripting XSS
 );
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/01");


 script_set_attribute(attribute:"plugin_type", value:"remote");

 script_end_attributes();

 script_category(ACT_END);
 script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses : XSS");

 script_dependencie("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl", "torture_cgi_persistent_XSS2.nasl");
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

port = get_kb_item("Services/www");
if (!port) exit(0, "No web server has been identified.");

report = "";
resp_l = get_kb_list("www/"+port+"/cgi_*/response/*");
if (isnull(resp_l)) exit(0);

prev_code = '';
foreach k (sort(keys(resp_l)))
{
  v = eregmatch(string: k, pattern: "/cgi_([A-Z][A-Z])/response/([0-9]+)");
  if (isnull(v)) continue;
  code = v[1]; nb = v[2];
  # Already known as an XSS?
  if (code =~ "^X") continue;

  rep1 = "";
  r = get_kb_blob("www/"+port+"/cgi_"+code+"/response/"+nb);
  if (isnull(r))
    r = decode_kb_blob(value: resp_l[k]);

  v = NULL; txt = NULL;

  foreach pa (refl_xss_patterns)
  {
    txt = extract_pattern_from_resp(string: r, pattern: pa);
    if (txt) break;
  }

  if (! txt) continue;

  r = chomp(get_kb_blob("www/"+port+"/cgi_"+code+"/request/"+nb));

  l = split(r, keep: 0);
  l = l[0];
  v = eregmatch(string: l, pattern: "^[A-Z]+ +(([^ ?][^?]*)(\?.*)?) +HTTP/1\.[01]$");
  if (! isnull(v))
  {
    page = v[2];
    # This is imperfect, as we extracted the page on which we saw the XSS, 
    # not the CGI on which the XSS was injected.
    if (already_known_flaw(port: port, cgi: page, vul: 'XP'))
    {
      debug_print(build_url(port:port, qs: page), ' is known to be vulnerable to persistent XSS.');
      continue;
    }
  }

  rep1= strcat(rep1, 
'\n-------- request  --------\n', 
r,
'\n-------- output --------\n', 
txt,
'------------------------\n\n');

  if (code != prev_code)
  {
    report = strcat(report,
'\nDuring testing for ', torture_cgi_name(code: code), ' vulnerabilities, ',
'\nattack pattern from XSS tests were seen, suggesting that the application',
'\nis also vulnerable to persistent cross-site scripting. \n');
    prev_code = code;
  }
  report += rep1;
}

if (strlen(report) > 0)
{
  security_warning(port:port, extra: report);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
