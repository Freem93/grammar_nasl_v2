#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57323);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/18 17:14:09 $");

  script_name(english:"OpenSSL Version Detection");
  script_summary(english:"Extracts the version from banner / error page.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to detect the OpenSSL version.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to extract the OpenSSL version from the web server's
banner. Note that security patches in many cases are backported and
the displayed version number does not show the patch level. Using it
to identify vulnerable software is likely to lead to false detections.");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("backport.inc");

port = get_http_port(default:80, embedded:1);

app_name = "OpenSSL";
pattern = "OpenSSL\/(\d+(?:\.\d+)*(-beta\d+|-pre\d+|[a-z]*))";

# Get the pristine banner first.
pristine_banner = http_server_header(port:port);

# If there is no mention of OpenSSL in the header, get the cached
# page, in case it's misconfigured Apache.
if (!preg(string:pristine_banner, pattern:pattern, icase:TRUE))
{
  # Hack for misconfigured Apache
  res = http_get_cache(port:port, item:'/', exit_on_fail:TRUE);
  lines = split(res, keep:0);
  if (lines[0] !~ "^HTTP/")
  {
    if ('<title>Bad request!</title>' >< res && '<h2>Error 400</h2>' >< res)
    {
      i1 = stridx(res, '<span>');
      if (i1 >= 0)
      {
        i2 = stridx(res, '</span>', i1);
	if (i2 >= 0)
	{
	  lines = split(substr(res, i1, i2), keep:0);
	  foreach line (lines)
	  {
	    match = eregmatch(pattern:pattern, string:line);
	    if (!isnull(match))
	    {
              pristine_banner = line;
	      break;
	    }
	  }
	}
      }
    }
  }
}

# nb: we need to check for a NULL banner since not all web servers
#     will have a Server response header or support the hack for
#     misconfigured Apache
if (isnull(pristine_banner)) exit(0, "The banner from port " + port + " does not have a Server response header.");

# Look for OpenSSL in the banner. If it's not there, audit out.
match = multiline_eregmatch(string:pristine_banner, pattern:pattern, icase:TRUE);
if (isnull(match)) audit(AUDIT_WEB_APP_NOT_INST, app_name, port);
pristine_version = match[1];


# Check if the banner is backported.
backported_version = NULL;
backported = FALSE;

backported_banner = get_backport_banner(banner:pristine_banner);
if (backported_banner != pristine_banner) backported = TRUE;
match = eregmatch(string:backported_banner, pattern:pattern, icase:TRUE);
if (!isnull(match)) backported_version = match[1];

# Save to KB.
kb_base = "openssl/" + port + "/";
set_kb_item(name:"openssl/port", value:port);
set_kb_item(name:kb_base + "pristine_banner", value:pristine_banner);
set_kb_item(name:kb_base + "pristine_version", value:pristine_version);

if (backported)
{
  set_kb_item(name:kb_base + "backported", value:TRUE);
  set_kb_item(name:kb_base + "backported_banner", value:backported_banner);

  if (!isnull(backported_version))
    set_kb_item(name:kb_base + "backported_version", value:backported_version);
}

# Report
if (report_verbosity > 0)
{
  report =
    '\n  Source             : ' + pristine_banner +
    '\n  Reported version   : ' + pristine_version;

  if (backported)
  {
    if (!isnull(backported_version)) report += '\n  Backported version : ' + backported_version;
    else report += '\n\nNessus determined that the server banner is backported.';
  }

  report += '\n';

  security_note(extra:report, port:port);
}
else security_note(port:port);
