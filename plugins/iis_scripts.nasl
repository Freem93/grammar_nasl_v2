#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2016/04/01. Webmirror3.nbin will identify browsable
# directories.

include("compat.inc");

if(description)
{
 script_id(10121);
 script_version ("$Revision: 1.32 $");
 script_cvs_date("$Date: 2016/12/30 22:07:39 $");

 script_osvdb_id(3268);

 script_name(english:"Microsoft IIS /scripts Directory Browsable (deprecated)");
 script_summary(english:"Checks if /scripts/ listable.");
 
 script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
 script_set_attribute(attribute:"description", value:
"The /scripts directory is browsable. This gives an attacker valuable
information about which default scripts you have installed and also
whether there are any custom scripts present that may have
vulnerabilities.

This plugin has been deprecated. Webmirror3 (plugin ID 10662) will
identify a browsable directory.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"vuln_publication_date", value: "1994/01/01");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Webmirror3 (plugin ID 10662) will identify a browsable directory.");

# The attack starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( "Microsoft-IIS" >!< banner ) exit(0);
if(get_port_state(port))
{
  res = http_send_recv3(method:"GET", item:"/scripts", port:port);
  if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

  if ((" 200 " >< res[1]) && ("<title>/scripts" >< res[2])) security_warning(port:port);
}
