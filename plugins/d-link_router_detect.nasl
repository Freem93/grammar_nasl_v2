#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44319);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/04/26 19:54:30 $");

  script_name(english:"D-Link Router Detection");
  script_summary(english:"Detects D-Link Routers");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is a D-Link router."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote device is a D-Link router.  These devices route packets and
may provide port forwarding, DMZ configuration and other networking
services."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.dlink.com/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Disable this hardware if it violates your corporate policy."
  );
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 8099);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

ports = add_port_in_list(list:get_kb_list("Services/www"), port:8099);
foreach port (ports)
{
  firmware = '';
  modelname = '';
  if (get_port_state(port))
  {
    dlink = FALSE;
    res = http_get_cache(item:"/", port:port, exit_on_fail: 0);
    if (!isnull(res))
    {
      if (service_is_unknown(port:port)) register_service(port:port, proto:"www");

      if ("<VendorName>D-Link Systems</VendorName>" >< res)
      {
        info = "";

        if ("<ModelName>" >< res && "</ModelName>" >< res)
        {
          modelname = strstr(res, "<ModelName>") - "<ModelName>";
          modelname = modelname - strstr(modelname, "</ModelName>");
          info += '\nModel             : ' + modelname;
          replace_kb_item(name:"d-link/model", value:modelname);
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
          replace_kb_item(name:"d-link/firmware", value:firmware);
        }

        replace_kb_item(name:"www/d-link", value:TRUE);
        replace_kb_item(name:"www/"+port+"/d-link", value:TRUE);
        replace_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE);

        dlink = TRUE;
			}
      else if ('D-LINK SYSTEMS, INC.' >< res)
      {
        info = "";

        if ('>Product Page :' >< res)
        {
          if ('<div class="pp">Product Page :' >< res)
          {
            modelname = strstr(res, '<div class="pp">Product Page :') - '<div class="pp">Product Page : ';
            modelname = modelname - strstr(modelname, '<a href');
          }
          else if ('<span class="product">Product Page :' >< res)
          {
            modelname = strstr(res, '<span class="product">Product Page :') - '<span class="product">Product Page : ';
            modelname = strstr(modelname, '>') - '>';
            modelname = modelname - strstr(modelname, '</a>');
          }

          if (modelname)
          {
            info += '\nModel             : ' + modelname;
            replace_kb_item(name:"d-link/model", value:modelname);
          }
        }
        if ('>Firmware Version' >< res)
        {
          if ('<div class="fwv">Firmware Version :' >< res)
          {
            firmware = strstr(res, '<div class="fwv">Firmware Version :') - '<div class="fwv">Firmware Version : ';
            firmware = firmware - strstr(firmware, '<span id="fw_ver"');
          }
          else if ('<span class="version">Firmware Version :' ><  res)
          {
            firmware = strstr(res, '<span class="version">Firmware Version :') - '<span class="version">Firmware Version : ';
            firmware = firmware - strstr(firmware, '</span>');
          }

          if (firmware)
          {
            info += '\nFirmware          : ' + firmware;
            replace_kb_item(name:"d-link/firmware", value:firmware);
          }
        }

        replace_kb_item(name:"www/d-link", value:TRUE);
        replace_kb_item(name:"www/"+port+"/d-link", value:TRUE);
        replace_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE);

        dlink = TRUE;
      }
    }
    if (dlink)
    {
      if (report_verbosity > 0 && info) security_note(port:port, extra:info);
      else security_note(port);
    }
  }
}
if (!dlink) audit(AUDIT_HOST_NOT, 'D-Link');
