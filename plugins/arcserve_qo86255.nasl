#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24816);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/10/07 13:30:46 $");

  script_cve_id("CVE-2006-6076", "CVE-2007-0816", "CVE-2007-1447", "CVE-2007-1448");
  script_bugtraq_id(21221, 22365, 22994);
  script_osvdb_id(30637, 32989, 32990, 32991);

  script_name(english:"CA BrightStor ARCserve Backup Tape Engine and Portmapper Multiple Vulnerabilities (QO86255)");
  script_summary(english:"Checks version of BrightStor ARCserve Backup");

  script_set_attribute(attribute:"synopsis", value:
"The remote software is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of BrightStor ARCserve
Backup on the remote host is affected by multiple buffer overflows
involving the application's Tape Engine and portmapper services.  An
unauthenticated, remote attacker may be able to leverage these issues
to crash or disable the services or to execute arbitrary code on the
affected host with SYSTEM privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?deaadc11");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Mar/265");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?deaadc11");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as described in the vendor advisory
referenced above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CA BrightStor ARCserve Tape Engine Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/16");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:arcserve_backup");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

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
    (ver == "11.5" && build < 4237) ||
    (ver == "11.1" && build < 3208) ||
    # nb: QI82917 says there's no patch for 11.0; the solution is to 
    #     upgrade to 11.1 and then apply QO86258.
    (ver == "11.0") ||
    # nb: QO86259 doesn't exist.
    (ver == "10.5") ||
    (ver == "9.0" && build < 2205)
  ) security_hole(port:port, proto:"udp");
}
