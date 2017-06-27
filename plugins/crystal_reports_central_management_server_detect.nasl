#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30051);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/05/11 13:46:37 $");

  script_name(english:"Crystal Reports Central Management Server Detection");
  script_summary(english:"Searches for a CMS");

  script_set_attribute(attribute:"synopsis", value:
"A report server is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote service is a Central Management Server (also known as
Crystal Management Server and Automated Process Scheduler), a key
component of Crystal Reports Server that centralizes information about
users, security levels, published objects, and servers.");
  script_set_attribute(attribute:"see_also", value:"https://www.sap.com/product/analytics/crystal-reports.html");
  script_set_attribute(attribute:"see_also", value:"https://www.sap.com/product/analytics/crystal-server.html");
  script_set_attribute(attribute:"solution", value:"Limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None" );

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:businessobjects:crystal_reports");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 6400);

  exit(0);
}



include("byte_func.inc");
include("corba_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  )
{
  port = get_unknown_svc(6400);
  if (!port) exit(0);
  if (silent_service(port)) exit(0); 
}
else port = 6400;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Try to connect.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

req = "aps";
send(socket:soc, data:req);
res = recv(socket:soc, length:4);

if (strlen(res) != 4) exit(0);
len = getdword(blob:res, pos:0);
if (len == 0 || len > 1024*1024) exit(0);
res = recv(socket:soc, length:len);
if (strlen(res) != len) exit(0);


# Try to parse the IOR.
ior = ior_destringify(str:res);
if (isnull(ior)) exit(0);
obj = ior_unmarshal(ior:ior);


# If it looks right...
if (
  !isnull(obj) && 
  "IDL:img.seagatesoftware.com/ImplServ/OSCAFactory" >< obj['type_id']
)
{
  # Try to get the version.
  ver = NULL;

  if (NASL_LEVEL >= 4002)
  {
    nprofiles = obj['nprofiles'];
    if ( nprofiles > 1024 ) nprofiles = 1024;
    for (i=1; i<=nprofiles; i++)
    {
      profile_id = obj['profile_'+i];
      if (TAG_INTERNET_IOP == profile_id)
      {
        iiop = iiop_unmarshal_profile(str:obj['profile_'+i+'_data']);
        port2 = iiop['port'];
        if (port2 > 0 && port2 <= 65535)
        {
          soc2 = open_sock_tcp(port2);
          if (soc2)
          {
            # Send a GIOP request for the version number.
            giop_req['version'] = "1.1";
            giop_req['service_context_list'] = raw_string(
              0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
              0x0c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
              0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00
            );
            giop_req['request_id'] = 0;
            giop_req['response_expected'] = TRUE;
            giop_req['object_key'] = iiop['object_key'];
            giop_req['operation'] = "versionInfo";
            giop_req['requesting_principal'] = "";

            req2 = giop_marshal_request(req:giop_req);
            send(socket:soc2, data:req2);
            res2 = recv(socket:soc2, length:1024, min:4);
            close(soc2);
            giop_rep = giop_unmarshal_reply(str:res2);

            if (
              !isnull(giop_rep) &&
              GIOP_REPLYSTATUS_NO_EXCEPTION == giop_rep['reply_status']
            )
            {
              body = giop_rep['body'];
              if (strlen(body))
              {
                wstr = cdr_unmarshal_wstring(blob:body, pos:0);

                ver = "";
                for (i=0; i<strlen(wstr); i+=2)
                {
                  ver += wstr[i];
                  if (ord(wstr[i+1]) != 0)
                  {
                    ver = "";
                    break;
                  }
                }
                if (strlen(ver))
                {
                  set_kb_item(name:"CrystalReports/CMS/"+port+"/Version", value:ver);
                }
              }
            }
          }
        }
      }
    }
  }

  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"crystal_reports_cms");

  if (ver && report_verbosity > 0)
  {
    report = string(
      "\n",
      "The remote version of Crystal Reports Server is ", ver, "."
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
