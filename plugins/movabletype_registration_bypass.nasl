#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55410);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/07/24 23:43:30 $");

  script_bugtraq_id(48195);
  script_osvdb_id(72885);

  script_name(english:"Movable Type User Registration Restriction Bypass");
  script_summary(english:"Tries to register a user in blogs that have disabled that feature");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A blog running on the remote web server has a restriction bypass
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Movable Type running on the remote host has a
restriction bypass vulnerability.  It is possible to create new user
accounts even when registration has been disabled in the blog
configuration.

A remote attacker could exploit this to register new accounts for
blogs that do not allow registration.

This version of Movable Type likely has other unspecified
vulnerabilities although Nessus has not checked for them."
  );
  # http://www.movabletype.org/2011/06/movable_type_511_and_5051_4361_security_updates.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fca822be");
  script_set_attribute(attribute:"solution", value:"Upgrade to Movable Type 4.361 / 5.051 / 5.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sixapart:movable_type");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

  script_dependencies("movabletype_detect.nasl");
  script_require_keys("www/movabletype");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);
install = get_install_from_kb(appname:'movabletype', port:port, exit_on_fail:TRUE);

# send an invalid registration request that will fail, yet
# allow us to fingerprint the vulnerable behavior
postdata =
  '__mode=do_signup' +
  '&username=' + unixtime() +
  '&nickname=' + unixtime() +
  '&email=' + SCRIPT_NAME + '@example.com';
url = install['dir'] + '/mt-comments.cgi';
res = http_send_recv3(
  method:'POST',
  item:url,
  port:port,
  content_type:'application/x-www-form-urlencoded',
  data:postdata,
  exit_on_fail:TRUE
);

install_url =  build_url(qs:install['dir'],port:port);

# vulnerable installs will say we're missing data (user password)
# patched installs will say the entire request was invalid (blog id missing)
expected_output = 'User requires password';
if (expected_output >< res[2])
{
  if (report_verbosity > 0)
  {
    report =
      '\nNessus fingerprinted the vulnerability by making the following request :\n\n' +
      crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30)+'\n'+
      http_last_sent_request() + '\n' +
      crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30)+'\n';

    if (report_verbosity > 1)
    {
      report +=
        '\nWhich resulted in the following error message :\n\n' +
        crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30)+'\n'+
        extract_pattern_from_resp(string:res[2], pattern:'ST:' + expected_output) +
        crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30)+'\n';
    }

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else if ('Invalid request' >< res[2])
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Movable Type", install_url);
else
  exit(0, 'Unexpected response received from the Movable Type install at '+install_url+ ".");
