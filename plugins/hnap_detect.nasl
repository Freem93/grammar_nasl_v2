#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description) 
{
  script_id(44318);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/06/03 21:40:31 $");

  script_name(english:"HNAP Detection");
  script_summary(english:"Detects HNAP on devices"); 
 
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device has HNAP enabled."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote service supports the Home Network Administration Protocol
(HNAP), a SOAP-based protocol that provides a common interface for
administrative control of networked devices."
  );
  # http://web.archive.org/web/20100324094727/http://hnap.org/
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?78450add"
  );
  # http://www.cisco.com/web/partners/downloads/guest/hnap_protocol_whitepaper.pdf
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?1b0ee657"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Limit incoming traffic to this port if desired."
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

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

ports = add_port_in_list(list:get_kb_list("Services/www"), port:8099);
foreach port (ports)
{
  if (get_port_state(port))
  {
    res = http_get_cache(item:"/HNAP1/", port:port, exit_on_fail:FALSE);
    if (!isnull(res))
    {
      if (service_is_unknown(port:port)) register_service(port:port, proto:"www");

      if (
        "<SOAPActions>" >< res &&
        "http://purenetworks.com/HNAP1" >< res
      )
      {
        replace_kb_item(name:"www/hnap",value:TRUE);
        replace_kb_item(name:"www/"+port+"/hnap",value:TRUE);
        replace_kb_item(name:"Services/www/"+port+"/embedded",value:TRUE);

        security_note(port);
        exit(0);
      }
    }
  }
}
