#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32398);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/11/11 19:58:29 $");

  script_cve_id("CVE-2008-2241", "CVE-2008-2242");
  script_bugtraq_id(29283);
  script_osvdb_id(45367, 45368);
  script_xref(name:"Secunia", value:"30300");

  script_name(english:"CA BrightStor ARCserve Backup Multiple Vulnerabilities (QO92996)");
  script_summary(english:"Checks version of BrightStor ARCserve Backup");

  script_set_attribute(attribute:"synopsis", value:
"The remote software is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of BrightStor ARCserve
Backup on the remote host is affected by multiple issues :

  - A vulnerability in 'caloggerd' could allow an 
    unauthenticated attacker to append data to arbitrary 
    files on the server using log messages with directory
    traversal sequences, which could lead to a system
    compromise.

  - Insufficient boundary checks in multiple 'xdr' 
    functions could allow an unauthorized attacker to 
    execute arbitrary code with SYSTEM level privileges 
    or cause a denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-026/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-027/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/May/207");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/May/216");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/May/210");
  # https://support.ca.com/irj/portal/anonymous/phpsupcontent?contentID=176798
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d7e28a0b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ARCserve Backup r11.5 SP4/ r12.0
or apply vendor-supplied patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22, 119);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/22");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:arcserve_backup");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("arcserve_discovery_service_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("ARCSERVE/Discovery/Version");

  exit(0);
}

os = get_kb_item("Host/OS");
if (!os || "Windows" >!< os) exit(0);

include("global_settings.inc");

ver = get_kb_item("ARCSERVE/Discovery/Version");
if (!ver) exit(0);

# Exit on version 12.0 or r11.5 SP4
if ("r12.0" >< ver || "r11.5 (build 4490)"  >< ver ) exit(0);

port = get_kb_item("Services/udp/casdscsvc");
if (!port) exit(0);

matches = eregmatch(string:ver, pattern:"^[a-z]([0-9]+\.[0-9]+) \(build ([0-9]+)\)$");
if (!isnull(matches))
{
  ver 	= matches[1];
  build = int(matches[2]);

  if (
      (ver == "11.5" && build < 4408) ||
      (ver == "11.1" && build < 3212) ||
      # nb: Users should upgrade to at least r11.1 and apply relevant patches.
      (ver == "11.0")
     )
  {
    if (report_verbosity)
    { 	
      report = string(
        "\n",
        "Arcserve Backup ", ver , " ( build ",build,") is installed on the remote host.\n"
      );
      security_hole(port:port, proto:"udp", extra:report);
    }
    else security_hole(port:port, proto:"udp");
  }
}
