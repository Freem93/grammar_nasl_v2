#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45138);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/09 20:54:57 $");

  script_name(english:"Remote Help Default Credentials");
  script_summary(english:"Attempts to log in to Remote Help with default credentials.");

  script_set_attribute(attribute:"synopsis", value:"The remote access service uses a default set of credentials.");
  script_set_attribute(attribute:"description", value:
"It was possible to log in to the Remote Help server on the remote host
using a default set of credentials. 

An attacker could exploit this flaw in order to gain complete control of
the affected system."
  );
  script_set_attribute(attribute:"see_also", value:"http://remotehelp.sourceforge.net/en/index.html");
  script_set_attribute(attribute:"solution", value:"Change the password for the default user.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("remotehelp_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/remote_help");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


login = 'user';
pass = 'default';

ports = get_kb_list("www/remote_help/*");
if (isnull(ports)) exit(0, "Remote Help has not been detected.");
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

foreach key (keys(ports))
{
  port = key - "www/remote_help/";
  url = '/intro';
  postdata = 'user='+login+'&pass='+pass;

  req = http_mk_post_req(
    port        : port,
    item        : url,
    data        : postdata,
    content_type: "application/x-www-form-urlencoded"
  );
  res = http_send_recv_req(port:port, req:req);
  if (isnull(res)) continue;

  if (
    res[2] &&
    '<a href=/shot>Deskshot</a>' >< res[2] &&
    '<a href=/process>Threads</a>' >< res[2] &&
    '<a href=/exit>Exit</a>' >< res[2] &&
    '<a href=http://remotehelp.sf.net>Remote Help </a>' >< res[2]
  )
  {
    if (report_verbosity > 0)
    {
      report = '\n' +
        'Nessus was able to gain access using the following information :\n' +
        '\n' +
        '  URL      : ' + build_url(port:port, qs:url) + '\n' +
        '  User     : ' + login + '\n' +
        '  Password : ' + pass + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port:port);
  }
}
exit(0, 'The Remote Help install(s) are not affected.');
