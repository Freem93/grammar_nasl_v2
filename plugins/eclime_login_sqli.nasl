#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45065);
  script_version("$Revision: 1.6 $");
 script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_bugtraq_id(38625);
  script_osvdb_id(62812);
  script_xref(name:"Secunia", value:"38307");

  script_name(english:"eclime login.php SQL Injection");
  script_summary(english:"Tries an injection that leads to an error message");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host has a SQL injection
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of eclime running on the remote web server has a SQL
injection vulnerability.  The application fails to properly sanitize
input passed to the 'email_address' and 'password' parameters of
'login.php'.

Regardless of PHP's 'magic_quotes_gpc' setting, a remote attacker
can exploit this by making a specially crafted POST request,
which would result in the execution of arbitrary SQL queries."
  );
  # http://web.archive.org/web/20120507093322/http://www.eclime.com/forum/viewtopic.php?f=21&t=248
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b4b900ca");
  script_set_attribute(attribute:"solution", value:"Upgrade to eclime 1.1.1b or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("oscommerce_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/eclime");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80);

install = get_install_from_kb(appname:'eclime', port:port);
if (isnull(install))
  exit(1, "No eclime installs on port "+port+" were found in the KB.");

# Make sure the page exists before POSTing
url = install['dir'] + '/login.php?action=process';
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if (
  '<input type="text" name="email_address"' >!< res[2] ||
  '<input type="password" name="password"' >!< res[2]
) exit(1, 'Error requesting '+build_url(qs:url, port:port));

# then attempt the sql injection
email = "'"+SCRIPT_NAME;
pass = string(unixtime());
postdata =
  'email_address='+email+
  '&password='+pass;
req = http_mk_post_req(
  port:port,
  item:url,
  data:postdata,
  content_type:'application/x-www-form-urlencoded'
);
res = http_send_recv_req(port:port, req:req, exit_on_fail:TRUE);

if (
  'You have an error in your SQL syntax' >< res[2] &&
  "AND user_name = '"+email+"'" >< res[2] &&
  "AND password = '"+pass+"'" >< res[2]
)
{
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\nNessus detected this issue by sending the following request :\n\n'+
      crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30)+'\n'+
      http_mk_buffer_from_req(req:req)+'\n'+
      crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30)+'\n';

    if (report_verbosity > 1)
    {
      error = strstr(res[2], '1064 - You have an error in your SQL syntax');
      extra = strstr(error, '<br><br><small>');
      error -= extra;
      report +=
        '\nWhich resulted in the following error :\n\n'+
        crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30)+'\n'+
        error+'\n'+
        crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30)+'\n';
    }
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else
{
  eclime_site = build_url(qs:install['dir'], port:port);
  exit(0, "The eclime site at " + eclime_site + " is not affected.");
}
