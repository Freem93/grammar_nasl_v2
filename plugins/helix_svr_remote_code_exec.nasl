#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(35555);
 script_version ("$Revision: 1.8 $");

 script_cve_id("CVE-2008-5911");
 script_bugtraq_id(33059);
 script_osvdb_id(53204, 53205, 53206, 53207);
 script_xref(name:"Secunia", value:"33360");
 
 script_name(english:"RealNetworks Helix Server < 11.1.8/12.0.1 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote media streaming server is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of RealNetworks Helix Server
older than 11.1.8 / 12.0.1.  Such versions are reportedly affected by
multiple issues :

  - A vulnerability involving an RTSP 'DESCRIBE' request 
    could  allow an unauthenticated attacker to execute 
    arbitrary code on the remote system. (ZDI-CAN-293)

  - By sending three specially crafted RTSP 'SETUP' requests
    it may be possible to crash the remote RTSP server. 
    (ZDI-CAN-323)
 
  - A heap overflow vulnerability in 'DataConvertBuffer',
    could allow an unauthenticated attacker to execute 
    arbitrary code on the remote system. (ZDI-CAN-333)

  - A heap overflow vulnerability in NTLM Authentication
    could allow an unauthenticated attacker to execute 
    arbitrary code on the remote system. (ZDI-CAN-380)" );
 script_set_attribute(attribute:"see_also", value:"http://docs.real.com/docs/security/SecurityUpdate121508HS.pdf" );
 script_set_attribute(attribute:"solution", value:
"Update to RealNetworks Helix Server 11.1.8 / 12.0.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/01/30");
 script_cvs_date("$Date: 2011/03/21 01:44:55 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks version of RealNetworks Helix Server");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencies("rtsp_detect.nasl");
 script_require_ports("Services/rtsp", 554);
 exit(0);
}

include("global_settings.inc");

port = get_kb_item("Services/rtsp");
if ( ! port ) port = 554;

if (!get_port_state(port)) exit(0);

serv = get_kb_item(string("rtsp/server/",port));

if (!serv || !ereg(pattern:"Helix (Mobile|) *Server Version",string:serv)) exit(0);

# Currently, versions  11.x ( < 11.1.8) and 12.x (< 12.0.1) are affected 

if (
  ereg(pattern:"Version 11\.(0\.[0-9]|1\.[0-7]($|[^0-9]))", string:serv) ||
  ereg(pattern:"Version 12.0.0[^0-9]", string:serv)
) 
{
  if (report_verbosity)
  { 
    report = string(
      '\n',
      'The remote Helix server responded with the following banner :\n',
      '\n',
       '  ', serv,'\n'
    );
    security_hole(port:port,extra:report);
  }
  else security_hole(port);
}
