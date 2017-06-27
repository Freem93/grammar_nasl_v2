#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45543);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2012/02/28 16:14:31 $");

  script_cve_id("CVE-2010-1317", "CVE-2010-1318", "CVE-2010-1319");
  script_bugtraq_id(39490, 39561, 39564);
  script_xref(name:"OSVDB", value:"63919");
  script_xref(name:"OSVDB", value:"63920");
  script_xref(name:"OSVDB", value:"63922");
  script_xref(name:"Secunia", value:"39279");

  script_name(english:"RealNetworks Helix Server 11.x / 12.x / 13.x Multiple Vulnerabilities");
  script_summary(english:"Checks version in banner.");

  script_set_attribute(attribute:"synopsis", value:
"The remote media streaming server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running version 11.x,
12.x, or 13.x of RealNetworks Helix Server / Helix Mobile Server. 
Such versions are potentially affected by multiple vulnerabilities :

  - A heap overflow exists in the NTLM authentication code 
    related to invalid Base64 encoding. (CVE-2010-1317)

  - A stack-based buffer overflow within AgentX++ could
    lead to arbitrary code execution. (CVE-2010-1318)

  - An integer overflow within AgentX++ could lead to
    arbitrary code execution. (CVE-2010-1319)");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5d74423");
  script_set_attribute(attribute:"solution", value:"Upgrade to RealNetworks Helix Server / Helix Mobile Server 14.0.0 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'AgentX++ Master AgentX::receive_agentx Stack Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/15");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");
  script_family(english:"Misc.");
  script_dependencies("rtsp_detect.nasl");
  script_require_ports("Services/rtsp", 554);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"rtsp", default:554, exit_on_fail:TRUE);
if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");

serv = get_kb_item("rtsp/server/"+port);
if (!serv) exit(1, "The 'rtps/server/"+port+"' KB item is missing.");

if (!ereg(pattern:"Helix (Mobile|) *Server Version", string:serv))
  exit(0, "The banner from the RTSP service on port "+port+" is not from Helix Server or Helix Mobile Server.");

# Versions 11.x, 12.x, and 13.x are affected.
matches = eregmatch(pattern:"Helix (Mobile|) *Server Version ([0-9\.]+)", string:serv);
if (!matches) exit(1, "Nessus failed to extract the version from the banner of Helix server listening on port "+port+".");

version = matches[1];
if (ereg(pattern:"^1[123]($|[^0-9])", string:version))
{
  if (report_verbosity > 0)
  {
    report = 
      '\nThe Helix server responded with the following banner :'+
      '\n'+
      '\n  '+ serv+'\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port:port);
}
else exit(0, "The Helix server listening on port "+port+" is not affected because it is version "+version+".");
