#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84344);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 23:21:21 $");

  script_name(english:"Splunk Unsupported Version Detection");
  script_summary(english:"Checks the version to see if it's EOL.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version Splunk.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Splunk on the remote
host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://docs.splunk.com/Documentation/Splunk");
  # http://docs.splunk.com/Documentation/Splunk/3.0/ReleaseNotes/WhatsNewInSplunk30
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3179dbe5");
  # http://docs.splunk.com/Documentation/Splunk/4.0/SearchReference/WhatsInThisManual
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf8b87ef");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Splunk that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("splunkd_detect.nasl","splunk_web_detect.nasl");
  script_require_ports("Services/www", 8089, 8000);
  script_require_keys("installed_sw/Splunk");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Splunk";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8000, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);
version = install['version'];
install_url = build_url(qs:install['path'], port:port);

# End of Life Announcements for 3.x+ shown on manual pages
# 1.X / 2.X assumed at end of life because no patches have
# been released in years and 3.x and 4.x have been at end
# of life for more than two years.
eol_data = make_array();
eol_data["^[1-2]\."] = make_array(
  'date', 'Unknown',
  'url' , 'None, but assumed based on higher versions being EOL.'
);
eol_data["^3\."] = make_array(
  'date', 'December 31, 2012',
  'url' , 'http://docs.splunk.com/Documentation/Splunk/3.0/ReleaseNotes/WhatsNewInSplunk30'
);
eol_data["^4\."] = make_array(
  'date', 'October 1, 2013',
  'url' , 'http://docs.splunk.com/Documentation/Splunk/4.0/SearchReference/WhatsInThisManual'
);

supported = "5.x \ 6.x";

report = FALSE;
foreach vergx (keys(eol_data))
{
  if(version =~ vergx)
  {
    date   = eol_data[vergx]['date'];
    doc    = eol_data[vergx]['url' ];
    report = 
      '\n  URL                : '+ install_url +
      '\n  Installed version  : '+ version +
      '\n  EOL date           : '+ date +
      '\n  Announcement       : '+ doc +
      '\n  Supported versions : '+supported+
      '\n';
    register_unsupported_product(
      product_name : app, 
      version      : version, 
      cpe_base     : tolower(app) + ":" + tolower(app)
    );
    break;
  }
}

if(report)
{
  if (report_verbosity > 0) 
    security_hole(port:port, extra:report);
  else
    security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
