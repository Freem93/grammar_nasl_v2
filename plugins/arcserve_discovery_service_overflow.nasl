#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23841);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2011/10/21 01:22:51 $");

  script_cve_id("CVE-2006-6379");
  script_bugtraq_id(21502);
  script_osvdb_id(30775);

  script_name(english:"CA BrightStor ARCserve Backup Discovery Service Overflow");
  script_summary(english:"Checks version of BrightStor ARCserve Backup");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of BrightStor ARCserve
Backup on the remote host allows an attacker to execute arbitrary code
on the affected host with SYSTEM privileges due to a buffer overflow
that can be triggered by a specially crafted packet sent to the
Discovery Service. 

Note that the vendor reports only Windows installs are vulnerable.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?34d9360c");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/453916/100/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Either apply the appropriate patch as described in the vendor advisory
referenced above or upgrade to BrightStor ARCserve Backup r11.5 SP2 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:arcserve_backup");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("arcserve_discovery_service_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("ARCSERVE/Discovery/Version");

  exit(0);
}


os = get_kb_item("Host/OS");
if (!os || "Windows" >!< os) exit(0);


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
    (ver == "11.5" && build < 4232) ||
    (ver == "11.1" && build < 3205) ||
    # nb: QI82917 says there's no patch for 11.0; the solution is to 
    #     upgrade to 11.1 and then apply QO82863.
    (ver == "11.0") ||
    # nb: QO84611 doesn't exist.
    (ver == "10.5") ||
    (ver == "9.0" && build < 2203)
  ) security_hole(port:port, proto:"udp");
}
