#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49070);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/06/23 19:48:38 $");

  script_name(english:"Splunk Free Detection");
  script_summary(english:"Reports if the target is running Splunk Free.");

  script_set_attribute(attribute:"synopsis", value:
"An infrastructure monitoring tool is running on the remote host, and
it is protected using default administrator credentials.");
  script_set_attribute(attribute:"description", value:
"Splunk Free is running on the remote host. Splunk Free allows
uncredentialed access, and anyone who connects will automatically be
logged on as 'admin'. A remote attacker can exploit this to gain
administrative access to the application.

Splunk is a search, monitoring, and reporting tool for system
administrators.");
  # http://docs.splunk.com/Documentation/Splunk/latest/Admin/MoreaboutSplunkFree
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?978c0d35");
  script_set_attribute(attribute:"solution", value:
"Either limit incoming traffic to this port or upgrade to Splunk
Enterprise.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

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
  port     : port
);

license = install['License'];

if(!license)
  exit(0, "Could not determine the license of the Splunk install listening on port "+port+".");

if (license == "Free")
{
  report = NULL;
  if(report_verbosity > 0)
    report = '\n  Splunk with a Free license was found to be running. Upgrade to an Enterprise license.\n';
  security_hole(port:port,extra:report);
  exit(0);
} else audit(AUDIT_WEB_APP_NOT_INST, app+" with a Free License",port);
