#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20813);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2011/03/17 11:28:56 $");

  name["english"] = "TiVo Detection";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is a personal video recorder (PVR)." );
 script_set_attribute(attribute:"description", value:
"The remote host is a TiVo, a personal video recorder." );
 script_set_attribute(attribute:"solution", value:
"Make sure that use of such devices is in line with your organization's
security policy." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/29");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Detects a TiVo";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports(80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( ! get_port_state(80) ) exit(0, "Port 80 is not open");
banner = get_http_banner(port:80);
if ( "Server: tivo-httpd-" >!< banner ) exit(0, "the web server is not Tivo");

 if (report_verbosity)
 {
  version = egrep(pattern:"^Server: tivo-httpd", string:banner);
  os_version = ereg_replace(pattern:"^Server: tivo-httpd-1:(.*)", replace:"\1", string:version);

  report = '\n' + 'The remote TiVO is running TiVO software version ' + os_version + '\n';
  security_note(port:0, extra:report);
 }
 else security_note(0);