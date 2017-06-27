#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25086);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/10/07 15:36:47 $");

  script_cve_id("CVE-2007-1785", "CVE-2007-2139");
  script_bugtraq_id(23209, 23635);
  script_osvdb_id(34126, 35326);
  script_xref(name:"TRA", value:"TRA-2007-02");

  script_name(english:"CA BrightStor ARCserve Backup Multiple Vulnerabilities (QO87569)");
  script_summary(english:"Checks version of BrightStor ARCserve Backup");

  script_set_attribute(attribute:"synopsis", value:
"The remote software is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of BrightStor ARCserve
Backup on the remote host is affected by multiple vulnerabilities
in the Mediasrv RPC service.

First, the service does not properly sanitize a string given as 
an argument to different RPC functions prior to calling the function
strncpy. By sending a specially crafted packet it is possible
to overflow a stack buffer.

The second vulnerability involves the handler given as an argument
for most RPC functions. The service does the check that the handler
is valid. By sending a specially crafted handler to those functions,
it is possible to redirect the execution flow.

An unauthenticated, remote attacker may be able to leverage these issues
to crash or disable the service or to execute arbitrary code on the
affected host with SYSTEM privileges.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2007-02");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c6c1e90");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-07-022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as described in the vendor advisory
referenced above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CA BrightStor ArcServe Media Service Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/24");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/30");

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


ver = get_kb_item("ARCSERVE/Discovery/Version");
if (isnull(ver)) exit(0);


port = get_kb_item("Services/udp/casdscsvc");
if (!port) exit(0);


matches = eregmatch(string:ver, pattern:"^[a-z]([0-9]+\.[0-9]+) \(build ([0-9]+)\)$");
if (!isnull(matches))
{
  ver = matches[1];
  build = int(matches[2]);

  if (
    (ver == "11.5" && build < 4403 && build > 4400) ||
    (ver == "11.5" && build < 4238) ||
    (ver == "11.1" && build < 3209) ||
    (ver == "11.0") ||
    (ver == "10.5" && build < 2688) ||
    (ver == "9.0" && build < 2206)
  ) security_hole(port:port, proto:"udp");
}
