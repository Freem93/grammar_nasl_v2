#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(35709);
 script_version("$Revision: 1.10 $");
 script_cvs_date("$Date: 2016/10/13 15:15:41 $");

 script_xref(name:"CERT", value:"361684");

 script_name(english: "UPnP Internet Gateway Device (IGD) Protocol Detection");
 script_summary(english: "Look for IGD in the UPnP information.");

 script_set_attribute(attribute:"synopsis", value:
"The remote device supports the IGD protocol.");
 script_set_attribute(attribute:"description", value:
"According to its UPnP data, the remote device is a NAT router which
supports the Internet Gateway Device (IGD) Standardized Device Control
Protocol. Therefore, the device is potentially vulnerable as the
protocol can allow an adjacent attacker to punch holes in your
firewall (e.g., via a malicious Flash animation or JavaScript).");
 script_set_attribute(attribute:"see_also", value:"https://github.com/filetofirewall/fof");
 script_set_attribute(attribute:"see_also", value:"http://www.gnucitizen.org/blog/flash-upnp-attack-faq/");
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Internet_Gateway_Device_Protocol");
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port or disable this service.");
 script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");

 script_set_attribute(attribute:"vuln_publication_date", value: "2008/01/14");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/02/19");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "Misc.");

 script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

 script_dependencie("upnp_www_server.nasl");
 script_require_keys("upnp/www");

 exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('audit.inc');

port = get_kb_item_or_exit('upnp/www');
location = get_kb_item_or_exit('upnp/'+port+'/location');

vuln = FALSE;
deviceTypes = get_kb_list('upnp/'+port+'/deviceType');
foreach (deviceType in deviceTypes)
{
  if ("urn:schemas-upnp-org:device:InternetGatewayDevice" >< deviceType)
  {
  	vuln = TRUE;
    set_kb_item(name:"upnp/"+port+"/www/igd", value:TRUE);
    report = '\nNessus found an IGD description at ' + location + '\n';
    security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
  }
}

if (!vuln) exit(0, 'The server at ' + location + ' is not affected.');
