#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69016);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/07/23 14:37:31 $");

  script_name(english:"VLC Web Interface Detection");
  script_summary(english:"Detects the VLC Web Interface for remote control");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is the web interface to a media player.");
  script_set_attribute(attribute:"description", value:"The remote web server is the web interface to VLC, a media player.");
  script_set_attribute(attribute:"see_also", value:"http://www.videolan.org/doc/play-howto/en/ch04.html#id590873");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080, embedded:FALSE);
wafnote = '';
url = "/";

res = http_get_cache(port:port, item:'/', exit_on_fail:TRUE);
if ('<title>VLC media player - Web Interface' >< res && res =~ '^HTTP/1\\.[01] 200 ')
{
  set_kb_item(name:"www/VLC/installed", value:TRUE);
  match = eregmatch(pattern:'VLC (([0-9])([0-9.]+)?) ([A-Za-z0-9]+) - Lua Web Interface', string:res);
  if (! isnull(match))
  {
    version = match[2] + match[3];
    codename = match[4];
    set_kb_item(name:"www/VLC/" + port + "/version", value:version);
    set_kb_item(name:"www/VLC/" + port + "/codename", value:codename);
  }
  else
  {
    version = "unknown";
    codename = "unknown";
  }
}
else if ('<a href="http://www.videolan.org">VideoLAN</a>' >< res && res =~ '^HTTP/1\\.[01] 403 ')
{
  set_kb_item(name:"www/VLC/installed", value:TRUE);
  version = "unknown";
  codename = "unknown";
  wafnote = '\n' + 'VLC had been detected, but access is restricted with an ACL.\n';
  set_kb_item(name:"www/VLC/" + port + "/acl", value:TRUE);
}
else
{
  audit(AUDIT_WRONG_WEB_SERVER, port, "VLC media player");
}
if (report_verbosity > 0)
{
  info =
    '\n  Version   : ' + version +
    '\n  Codename  : ' + codename +
    '\n ' + wafnote;
  security_note(port:port, extra:info);
}
else security_note(port);

