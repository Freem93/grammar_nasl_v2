#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(40350);
 script_version ("$Revision: 1.7 $");

 script_cve_id("CVE-2009-2533", "CVE-2009-2534");
 script_bugtraq_id(35731, 35732);
 script_osvdb_id(55981, 55982);
 script_xref(name:"Secunia", value:"35815");
 
 script_name(english:"RealNetworks Helix Server < 13.0.0 Multiple Remote DoS");
 script_set_attribute(attribute:"synopsis", value:
"The remote media streaming server is affected by multiple denial of
service vulnerabilities." );

 script_set_attribute(attribute:"description", value:
"According to its banner, The remote host is running version 12.x of
RealNetworks Helix Server / Helix Mobile Server.  Such versions are
reportedly affected by multiple issues :

  - By sending a specially crafted 'RTSP' (SET_PARAMETERS) 
    request with a 'DataConvertBuffer' parameter and either
    no 'Content-Length' header or an invalid 'Content-Length'
    header, an attacker may be able to crash the remote Helix 
    server process. (CVE-2009-2533)

  - By sending a 'SETUP' request without including a '/' 
    character in it, a remote attacker may be able to crash
    the remote Helix server process. (CVE-2009-2534)" );

 script_set_attribute(attribute:"see_also", value:"http://www.coresecurity.com/content/real-helix-dna" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2009/Jul/121" );
 script_set_attribute(attribute:"see_also", value:"http://docs.real.com/docs/security/SecurityUpdate071409HS.pdf" );

 script_set_attribute(attribute:"solution", value:
"Update to RealNetworks Helix Server / Helix Mobile Server 13.0.0 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20);
  
 script_set_attribute(attribute:"vuln_publication_date",   value:"2009/07/17");
 script_set_attribute(attribute:"patch_publication_date",  value:"2009/07/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");

 script_cvs_date("$Date: 2016/10/10 15:57:06 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_summary(english:"Checks version in banner.");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencies("rtsp_detect.nasl");
 script_require_ports("Services/rtsp", 554);
 exit(0);
}

include("global_settings.inc");

port = get_kb_item("Services/rtsp");
if ( ! port ) port = 554;

if (!get_port_state(port)) exit(0);

serv = get_kb_item(string("rtsp/server/",port));

if (!serv || !ereg(pattern:"Helix (Mobile|) *Server Version",string:serv)) 
  exit(0,"Banner not from Helix Server or Helix Mobile Server.");

# Versions 12.x are affected 

if (ereg(pattern:"Version 12", string:serv)) 
{
  if (report_verbosity > 0)
  { 
    report = string(
      '\n',
      'The remote Helix server responded with the following banner :\n',
      '\n',
       '  ', serv,'\n'
    );
    security_warning(port:port,extra:report);
  }
  else security_warning(port);
}
