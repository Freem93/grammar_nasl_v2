#
# (C) Tenable Network Security, Inc.
#

# Thanks to Jason Haar for his help!

include("compat.inc");

if (description)
{
  script_id(35029);
  script_version("$Revision: 1.31 $");
  script_cvs_date("$Date: 2017/02/07 16:37:12 $");

  script_name(english:"Dell Remote Access Controller Default Password (calvin) for 'root' Account");
  script_summary(english:"Attempts to log into remote DRAC/iDRAC.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is protected using a known set of credentials.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to gain access to the Integrated Dell Remote Access
Controller (iDRAC) using a known set of credentials ('root' /
'calvin'). A remote attacker can exploit this issue to take full
control of the hardware.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Dell_DRAC");
  # https://www.dell.com/learn/us/en/555/solutions/integrated-dell-remote-access-controller-idrac
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3905db92");
  script_set_attribute(attribute:"solution", value:
"Change the password or disable this account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:X/RC:X");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:remote_access_card");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:idrac6");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:idrac7");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "drac_detect.nasl");
  script_require_ports("Services/www", 443);
  script_require_keys("installed_sw/iDRAC");
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "iDRAC";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:443, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

version = install['version'];

enable_cookiejar();

i = 0;
drac_field = NULL;
drac_url = NULL;

if (version =~ "^4")
{
  drac_field[i] = "hash";
  drac_url[i] = "/cgi/login";
}
else if (version =~ "^5")
{
  drac_field[i] = "password";
  drac_url[i] = "/cgi-bin/webcgi/login";
}
# Versions 6 & 7
else
{
  drac_field[i] = "password";
  drac_url[i] = "/data/login";
}

function test_drac(port, username, password)
{
  local_var r, extra, f;

  for (i = 0; drac_field[i]; i ++)
  {
    clear_cookiejar();
    r = http_send_recv3(port: port, method: 'POST', item: drac_url[i],
      data: strcat("user=", username, "&", drac_field[i], "=", password),
      follow_redirect: 0,
      add_headers: make_array("Content-Type", "application/x-www-form-urlencoded")
    );
    if (isnull(r)) continue;  # Drac4 returns nothing?
    if (r[0] !~ "^HTTP/1\.[01] +404 ")
    {
      if (egrep(pattern: "^Set-Cookie2?:", string: r[1], icase: 1))
      {
        # Erratic FPs with some versions
        if ( 'var s_invalidlogin = ' >< r[2] &&
          'var sMsg = "2"' >< r[2] &&
          'if (parseInt(sMsg) == 2) out(s_invalidlogin);' >< r[2]
        )
          continue;

        # DRACv8 FPs:
        # - successful auth returns "<authResult>0</authResult>" in response
        # - auth failure returns "<authResult>1</authResult>" in response
        if ( '<authResult>1</authResult>' >< r[2]) continue;

        extra =
          '\nNessus was able to gain access using the following URL :\n' +
          '\n' + build_url(port: port, qs:drac_url[i]) +
          '\n\nand the following set of credentials :\n' +
          '\n  Username : ' +username+
          '\n  Password : ' +password+ '\n';
        security_report_v4(port:port, extra:extra, severity:SECURITY_HOLE);
        exit(0);
      }
    }
  }
}

test_drac(port: port, username: "root", password: "calvin");
audit(AUDIT_WEB_APP_NOT_AFFECTED, app + version, build_url(qs:install['path'], port:port));
