#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74469);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/11 20:40:00 $");

  script_name(english:"Web Server on Extended Support");
  script_summary(english:"Check if web server is in on extended support.");
  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of a web server that
may be on extended support.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the web server
installed on the remote host has transitioned to the extended support
phase of its life cycle. Continued access to new security updates
requires payment of an additional fee and / or configuration changes
to the package management tool. Otherwise, the host will likely be
missing security updates.");
  script_set_attribute(attribute:"solution", value:
"Ensure that the host subscribes to the vendor's extended support plan
and continues to receive security updates.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("obsolete_httpd.nasl");
  script_require_keys("www/extended_support");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("www/extended_support");

port = get_http_port(default:80);
kb = get_kb_item_or_exit("www/"+port+"/extended_support");

if (report_verbosity > 0) security_note(port:port, extra:kb);
else security_note(port);
