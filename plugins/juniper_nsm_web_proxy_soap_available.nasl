#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69876);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_name(english:"Juniper NSM Web Proxy SOAP Interface Detection");
  script_summary(english:"Detects NSM Web Proxy SOAP Interface");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is running a SOAP interface."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running the Juniper NSM Web Proxy SOAP API, which
allows 3rd party applications access to NSM servers."
  );
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=KB12730");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:netscreen-security_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 8443);
  script_dependencies("juniper_nsm_web_proxy_detect.nasl");
  script_require_keys("www/juniper_nsm_web_proxy");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8443);

example_service = get_kb_item_or_exit("www/" + port + "/juniper_nsm_web_proxy/soap_available");

if (report_verbosity > 0)
{
  report = '\nNessus was able to determine that SOAP services are available by' +
           '\ngrabbing the following WSDL document :\n\n' +
           '  ' + build_url(qs:example_service, port:port) + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
