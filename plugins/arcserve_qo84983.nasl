#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24015);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2015/11/18 21:03:57 $");

  script_cve_id("CVE-2006-5171","CVE-2006-5172","CVE-2006-6076","CVE-2006-6917","CVE-2007-0168","CVE-2007-0169");
  script_bugtraq_id(21221, 22005, 22006, 22010, 22015, 22016);
  script_osvdb_id(30637, 31317, 31318, 31319, 31320, 31327);

  script_name(english:"CA BrightStor ARCserve Backup Multiple Vulnerabilities (QO84983)");
  script_summary(english:"Checks version of BrightStor ARCserve Backup");

  script_set_attribute(attribute:"synopsis", value:
"The remote software is affected by multiple vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of BrightStor ARCserve
Backup on the remote host is affected by multiple buffer overflows
that can be exploited by an unauthenticated, remote attacker to execute
arbitrary code on the affected host with SYSTEM privileges." );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e175e643" );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?543ab108" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/456711/30/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?25216527" );
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as described in the vendor advisory." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CA BrightStor ARCserve Message Engine Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/15");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:arcserve_backup");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

  script_dependencies("arcserve_discovery_service_detect.nasl");
  script_require_keys("ARCSERVE/Discovery/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");


ver = get_kb_item("ARCSERVE/Discovery/Version");
if (isnull(ver)) exit(0);


matches = eregmatch(string:ver, pattern:"^[a-z]([0-9]+\.[0-9]+) \(build ([0-9]+)\)$");
if (!isnull(matches))
{
  ver = matches[1];
  build = int(matches[2]);

  if (
    (ver == "11.5" && build < 4235) ||
    (ver == "11.1" && build < 3207) ||
    # nb: QI82917 says there's no patch for 11.0; the solution is to 
    #     upgrade to 11.1 and then apply QO84984.
    (ver == "11.0") ||
    # nb: QO84986 doesn't exist.
    (ver == "10.5") ||
    (ver == "9.0" && build < 2204)
  )
  {
    # Issue a report for each open TCP port.
    tcp_ports = make_list(
      111,                             # Mediasvr service
      6502,                            # Tape Engine
      6503,                            # Message Engine
      6504                             # Message Engine
    );
    foreach port (tcp_ports)
    {
      # Make sure the port is open.
      if (get_port_state(port) && service_is_unknown(port:port))
      {
        soc = open_sock_tcp(port);
        if (soc)
        {
          close(soc);
          security_hole(port);
        }
      }
    }
    udp_ports = make_list(
      111                              # Mediasvr service
    );
    foreach port (udp_ports)
    {
      security_hole(port:port, proto:"udp");
    }
  }
}
