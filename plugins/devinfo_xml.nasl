#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(49110);
 script_version("$Revision: 1.2 $");
 script_cvs_date("$Date: 2011/03/14 21:48:03 $");

 script_name(english: "Device Information (devinfo.xml)");
 script_summary(english: "Grabs devinfo.xml file");

 script_set_attribute(attribute:"synopsis", value:"The remote web server provides device information.");
 script_set_attribute(attribute:"description", value:
"It was possible to download the file 'devinfo.xml' from the remote
web server. 

This file is intended to be read by a setup utility.  It contains a
description of the device, installation instructions and sometimes
credentials for an Internet subscription.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/04");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('http.inc');

port = get_http_port(default: 80, embedded: 1);

u = "/devinfo.xml";
w = http_send_recv3(port: port, item: u, method: "GET", exit_on_fail: 1);
if (w[0] =~ "^HTTP/1\.[01] 200")
{
  url = build_url(port: port, qs: u);
  if ('<?xml version="1.0"' >!< w[2]) exit(0, url + " does not look like XML.");
  if ('<teapi>' >!< w[2]) exit(0, url + " does not contain <teapi> XML tag.");

  if (report_verbosity > 0)
  {
    e = '\n' + url + ' contains :\n\n' + w[2] + '\n';
    security_note(port: port, extra: e);
  }
  else security_note(port);
  if (COMMAND_LINE) display(e);
}
