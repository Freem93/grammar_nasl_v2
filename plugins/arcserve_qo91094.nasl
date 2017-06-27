#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26970);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2017/04/28 14:01:58 $");

  script_cve_id(
   "CVE-2007-5325",
   "CVE-2007-5326",
   "CVE-2007-5327",
   "CVE-2007-5328",
   "CVE-2007-5329",
   "CVE-2007-5330",
   "CVE-2007-5331",
   "CVE-2007-5332"
  );
  script_bugtraq_id(24017, 24680, 26015);
  script_osvdb_id(
    41366,
    41367,
    41368,
    41369,
    41370,
    41371,
    41372,
    41373,
    41374,
    57055,
    57056
  );
  script_xref(name:"TRA", value:"TRA-2007-08");

  script_name(english:"CA BrightStor ARCserve Backup Multiple Remote Vulnerabilities (QO91094)");
  script_summary(english:"Checks version of BrightStor ARCserve Backup");

  script_set_attribute(attribute:"synopsis", value:
"The remote software is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of BrightStor ARCserve
Backup on the remote host is affected by multiple vulnerabilities
affecting multiple components.  A remote attacker can leverage these
issues to execute arbitrary code, cause a denial of service, or access
privileged functions without proper authorization.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2007-08");
  # https://web.archive.org/web/20071013005741/http://supportconnectw.ca.com/public/storage/infodocs/basb-secnotice.asp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c33d20f");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as described in the vendor advisory
referenced above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94, 119, 264, 399);

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:arcserve_backup");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

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
    (ver == "11.5" && build < 4406) ||
    (ver == "11.1" && build < 3211) ||
    # nb: there's no patch for 11.0; the solution is to upgrade 
    #     to 11.1 and then apply latest patches.
    (ver == "11.0") ||
    # nb: there's no patch for 10.5; the solution is to upgrade 
    #     to 11.5 and then apply latest patches.
    (ver == "10.5") ||
    (ver == "9.0" && build < 2207)
  ) security_hole(port:port, proto:"udp");
}
