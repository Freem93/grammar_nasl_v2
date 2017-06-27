#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93221);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_cve_id("CVE-2016-6255");
  script_bugtraq_id(92050);
  script_osvdb_id(141985);

  script_name(english:"Portable SDK for UPnP Devices (libupnp) HTTP Arbitrary File Write");
  script_summary(english:"Writes a file to the remote HTTP server.");

  script_set_attribute(attribute:"synopsis", value:
"An HTTP server running on the remote host is affected by a remote
arbitrary file write vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Portable SDK for UPnP Devices (libupnp) running on the remote
host is affected by a flaw that is triggered when handling HTTP POST
or GET requests. An unauthenticated, remote attacker can exploit this
to write arbitrary files to the web server file system.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2016/q3/102");
  # https://github.com/mjg59/pupnp-code/commit/be0a01bdb83395d9f3a5ea09c1308a4f1a972cbd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf271a68");
  script_set_attribute(attribute:"solution", value:
"No patch or upgrade currently exists. If libupnp is used as a
third-party library by a different application, contact the vendor of
that application for a fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libupnp_project:libupnp");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:portable_sdk_for_upnp_project:portable_sdk_for_upnp");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("upnp_www_server.nasl");
  script_require_ports("upnp/server");
  script_require_keys("upnp/www");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

appname = "libupnp";

port = get_kb_item_or_exit("upnp/www");
banner = get_kb_item_or_exit("upnp/"+port+"/www/banner"); 

if ("Portable SDK for UPnP devices" >!< banner) audit(AUDIT_HOST_NOT, 'affected');

name = rand_str(length:16);
resp = http_send_recv3(method:"POST",
                       port:port,
                       item:'/'+name,
                       host:get_host_ip(),
                       data:name);

if (isnull(resp)) exit(1, 'The uPnP server did not respond. This could be due to a known "max jobs" bug.');
if ("200 OK" >!< resp[0]) audit(AUDIT_INST_VER_NOT_VULN, appname);

resp = http_send_recv3(method:"GET",
                       port:port,
                       host:get_host_ip(),
                       item:'/'+name);

if (isnull(resp)) exit(1, 'The uPnP server did not respond. This could be due to a known "max jobs" bug.');

if ("200 OK" >< resp[0] && name == resp[2])
{
  report = 'Nessus created a new page at http://' + get_host_ip() + ':' + port + '/' + name;
  security_report_v4(port:port,
                     severity:SECURITY_WARNING,
                     extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname);
