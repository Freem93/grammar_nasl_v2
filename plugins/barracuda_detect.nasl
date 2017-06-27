#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49710);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/03/03 14:11:18 $");

  script_name(english:"Barracuda Spam & Virus Firewall Console Management Detection");
  script_summary(english:"Checks for Barracuda management console");

  script_set_attribute(
    attribute:"synopsis",
    value:"A management console is running on this port."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host appears to be a Barracuda Spam & Virus Firewall.
It allows connections to its web console management application.

Letting attackers know the type of firewall in use may help them focus
their attacks against the networks it protects."
  );
  script_set_attribute(attribute:"solution", value:"Filter incoming traffic to this port.");
  script_set_attribute(attribute:"risk_factor", value:"None" );

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:barracuda_networks:barracuda_spam_firewall");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
  script_require_ports(8000, "Services/www");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8000, embedded:TRUE);

# Grab the initial page.
url = "/cgi-bin/index.cgi";
res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

found = FALSE;
firmware = NULL;

# Version < 4.x
if (
  (
    '<title>Barracuda Spam Firewall: Welcome</title>' >< res[2] ||
    'onsubmit="password.value=calcMD5(password_entry.value+enc_key.value)' >< res[2] ||
    '/header_logo.cgi" alt="Barracuda Spam Firewall"' >< res[2]
  ) &&
  'script language=javascript src="/js_functions.' >< res[2] &&
  '<input type=hidden name=enc_key value=' >< res[2]
)
{
  found = TRUE;
  firmware = strstr(res[2], 'script language=javascript src="/js_functions.') -
    'script language=javascript src="/js_functions.';
  if ('.js" type=' >< firmware) firmware = firmware - strstr(firmware, '.js" type=');

  if (firmware !~ "^[0-9][0-9.]+[0-9]$") firmware = UNKNOWN_VER;

  install = add_install(
    dir  : url,
    port : port,
    ver  : firmware,
    appname : 'barracuda_spamfw'
  );
}

# Version >= 4.x
if ( (isnull(firmware)) && ("/cgi-mod/index" >< res[1]) )
{
  pat = 'href="/barracuda\\.css\\?v=([0-9\\.]+)';

  res = http_send_recv3(
    port   : port,
    method : "GET",
    item   : "/cgi-mod/index.cgi",
    exit_on_fail : TRUE
  );
  if ('Barracuda Spam & Virus Firewall: Welcome</title>' >< res[2] &&
     (line = egrep(pattern:pat, string:res[2]))
  )
  {
    found = TRUE;
    match = eregmatch(
      pattern : '/barracuda\\.css\\?v=((4|5)\\.[0-9\\.]+)',
      string  : line
    );
    if (!isnull(match)) firmware = match[1];

    # Versions >= 5.1.x
    else
    {
      res = http_send_recv3(
        method : "GET",
        port   : port,
        item   : "/cgi-mod/view_help.cgi",
        exit_on_fail : TRUE
      );
      match = eregmatch(pattern:pat, string:res[2]);
      if (!isnull(match))
          firmware = match[1];
    }

    install = add_install(
      dir  : '/cgi-mod/index.cgi',
      port : port,
      ver  : firmware,
      appname : 'barracuda_spamfw'
    );
  }
}

if (found)
{
  if (report_verbosity > 0)
  {
    report = get_install_report(
      display_name : "Barracuda Spam & Virus Firewall",
      installs     : install,
      port         : port
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else audit(AUDIT_NOT_LISTEN, "Barracuda Spam & Virus Firewall", port);
