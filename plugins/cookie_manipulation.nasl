#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44135);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_name(english:"Web Server Generic Cookie Injection");
  script_summary(english:"Checks for generic cookie injection vulnerability in a web server");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a cookie injection attack.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a web server that fails to adequately
sanitize request strings of malicious JavaScript.  By leveraging this
issue, an attacker may be able to inject arbitrary cookies.  Depending
on the structure of the web application, it may be possible to launch
a 'session fixation' attack using this mechanism.

Please note that :

  - Nessus did not check if the session fixation attack is
    feasible.

  - This is not the only vector of session fixation.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Session_fixation");
  script_set_attribute(attribute:"see_also", value:"http://www.owasp.org/index.php/Session_Fixation");
  script_set_attribute(attribute:"see_also", value:"http://www.acros.si/papers/session_fixation.pdf");
  script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/Session-Fixation");
  script_set_attribute(attribute:"solution", value:"Contact the vendor for a patch or upgrade.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default: 80, embedded: 1);

file = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789");
exts = make_list(
  "asp",
  "aspx",
  "pl",
  "cgi",
  "exe",
  "cfm",
  "html",
  "jsp",
  "php",
  "php3",
#  "phtml",
#  "shtml",
   "cfc",
   "nsf",
   "dll",
   "fts",
   "jspa",
   "kspx",
   "mscgi",
   "do",
   "htm",
   "idc",
   "x",
   ""
);

cookie_name = "test"+rand_str(charset: "abcdefghijklmnopqrstuvwxyz", length: 4);
cookie_val  = rand() % 10000 + 1;	# No 0
exploits = make_list(
  '<script>document.cookie="'+cookie_name+'='+cookie_val+';"</script>',
  '<meta http-equiv=Set-Cookie content="'+cookie_name+'='+cookie_val+'">'
);


failures = 0;

dirs_l = NULL;
# If we are in paranoid mode, we want to reduce the FPs anyway.
if (thorough_tests) dirs_l = cgi_dirs();

if (isnull(dirs_l)) dirs_l = make_list("/");

foreach dir (dirs_l)
{
  len = strlen(dir);
  if (len == 0 || dir[0] != "/")
  {
    dir = strcat("/", dir);
    len ++;
  }
  if (len > 1 && dir[len-1] != "/") dir = strcat(dir, "/");

foreach ext (exts)
{
  foreach exploit (exploits)
  {
    enc_exploit = exploit;
    if (" " >< exploit) enc_exploit = str_replace(find:" ", replace:"%20", string: enc_exploit);
    if ('"' >< exploit) enc_exploit = str_replace(find:'"', replace:"%22", string:enc_exploit);

    if (ext) urls = make_list(string(dir, file, ".", ext, "?", enc_exploit));
    else
      urls = make_list(
        # nb: does server check "filenames" for JavaScript?
        string(dir, enc_exploit),
        enc_exploit,
        # nb: how about just the request string?
        string(dir, "?", enc_exploit)
      );

    foreach url (urls)
    {
      # Try to exploit the flaw.
      r = http_send_recv3(method: "GET", item:url, port:port, fetch404: TRUE, follow_redirect: 2);
      if (isnull(r))
      {
        failures ++;
        if (failures > 3)
 	  exit(1, "The web server on port "+port+" did not answer");
	continue;
      }
      if (r[0] =~ "^HTTP/1\.[01] 30[12] ") continue;	# FP

      buf = r[2];

      if (! isnull(buf) && "meta" >< exploit)
      {
        # Extract the head part
	buf = tolower(buf);
        i1 = stridx(buf, "<head>");
	if (i1 < 0) buf = '';
	else
	{
	  i2 = stridx(buf, "</head>");
	  if (i2 < i1) buf = '';
	  else buf = substr(buf, i1, i2);
	}
      }
      flag = 0;
      if (exploit >< buf) flag = 1;
      else
      {
        v = get_any_http_cookie(name: cookie_name);
	if (v) flag = 1;
      }
      if (flag)
      {
        set_kb_item(name:string("www/", port, "/generic_cookie_injection"), value:TRUE);

        if (report_verbosity)
        {
          report = strcat('\nThe request string used to detect this flaw was :\n\n', url, '\n\nThe output was :\n\n', r[0], r[1], '\n');

	  idx = 0;
	  lines = split(r[2], keep: 1);
	  foreach l (lines)
	    if (exploit >< l) break;
	    else idx ++;
	  i1 = idx - 3;
	  if (i1 < 0) i1 = 0; else report = strcat(report, '[...]\n');
	  for (i = i1; i < idx + 3 && i < max_index(lines); i ++)
	    report = strcat(report, lines[i]);
	  if (i < max_index(lines)) report = strcat(report, '[...]\n');

          security_warning(port:port, extra:report);
	  if (COMMAND_LINE) display(report);
        }
        else security_warning(port);

        exit(0);
      }
    }
  }
}
}
