#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(44391);
 script_version("$Revision: 1.7 $");

 script_name(english:"Linksys Router Detection");
 script_summary(english:"Detects Linksys Routers");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote device is a Linksys router."
 );
 script_set_attribute(
   attribute:"description",
   value:
"The remote device is a Linksys router.  These devices route packets
and may provide port forwarding, DMZ configuration and other
networking services."
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.linksysbycisco.com/"
 );
 script_set_attribute(
   attribute:"solution",
   value:
"Ensure that use of this device agrees with your organization's
acceptable use and security policies."
 );
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"plugin_publication_date",value:"2010/02/04");
 script_cvs_date("$Date: 2011/02/26 16:28:12 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");

 script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded:TRUE);

res = http_get_cache(item:"/HNAP1/", port:port, exit_on_fail: 1);

if ("<VendorName>Linksys by Cisco</VendorName>" >< res)
{

  info = "";
  if ("<ModelName>" >< res && "</ModelName>" >< res)
  {
     modelname = strstr(res, "<ModelName>") - "<ModelName>";
     modelname = modelname - strstr(modelname, "</ModelName>");
     info += '\nModel             : ' + modelname;
     set_kb_item(name:"Linksys/ModelName", value:modelname);
  }

  if ("<ModelDescription>" >< res && "</ModelDescription>" >< res)
  {
     modeldesc = strstr(res, "<ModelDescription>") - "<ModelDescription>";
     modeldesc = modeldesc - strstr(modeldesc, "</ModelDescription>");
     info += '\nDescription       : ' + modeldesc;
  }

    if ("<FirmwareVersion>" >< res && "</FirmwareVersion>" >< res)
  {
     firmware = strstr(res, "<FirmwareVersion>") - "<FirmwareVersion>";
     firmware = firmware - strstr(firmware, "</FirmwareVersion>");
     info += '\nFirmware        : ' + firmware;
		 set_kb_item(name:"Linksys/FirmwareVersion", value: firmware);
  }

 replace_kb_item(name:"www/linksys",value:TRUE);
 replace_kb_item(name:"www/"+port+"/linksys",value:TRUE);
 replace_kb_item(name:"Services/www/"+port+"/embedded",value:TRUE);

  if (report_verbosity > 0 && info) security_note(port:port, extra:info);
  else security_note(port);
}
else exit(0, "The device does not look like a Linksys router based on a response from port "+port+".");
