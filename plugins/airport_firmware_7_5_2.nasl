#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51342);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/08/20 16:45:01 $");

  script_cve_id(
    "CVE-2008-4309", 
    "CVE-2009-2189", 
    "CVE-2010-0039", 
    "CVE-2009-1574", 
    "CVE-2010-1804"
  );
  script_bugtraq_id(32020, 34765, 45489, 45490, 45491);
  script_osvdb_id(49524, 54286, 70149, 70150, 70151);

  script_name(english:"Apple Time Capsule and AirPort Base Station Firmware < 7.5.2 (APPLE-SA-2010-12-16-1)");
  script_summary(english:"Checks firmware version through SNMP");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote network device is affected by multiple remote
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the firmware version collected via SNMP, the remote
Apple Time Capsule / AirPort Base Station / AirPort Extreme Base
Station is affected by multiple remote vulnerabilities. 

  - An integer overflow exists in the 
    'netsnmp_create_subtree_cache' function that can be 
    exploited using a specially crafted SNMPv3 packet to
    crash the SNMP server. (CVE-2008-4309)
  
  - A remote attacker may be able to crash the racoon
    daemon by sending specially crafted fragmented ISAKMP
    packets, thereby triggering a NULL pointer dereference.
    (CVE-2009-1574)
  
  - By sending a large number of Router Advertisement (RA) 
    and Neighbor Discovery (ND) packets, an attacker on the
    local network can exhaust the base station's resources, 
    causing it to restart unexpectedly. (CVE-2009-2189)
  
  - An attacker with write access to an FTP server inside 
    the NAT may be able to use a malicious PORT command to
    bypass IP-based restrictions for the service. 
    (CVE-2010-0039)
  
  - If the device has been configured to act as a bridge or
    configured in Network Address Translation (NAT) mode
    with a default host enabled (not the default), an
    attacker may be able to cause the device to stop 
    responding using a specially crafted DHCP reply.
    (CVE-2010-1804)"
  );
  # http://web.archive.org/web/20110408175458/http://support.apple.com/kb/HT3549
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?7875828e"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2010/Dec/msg00001.html"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the firmware to version 7.5.2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/17");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("snmp_airport_version.nasl");
  script_require_keys("Host/Airport/Firmware");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/Airport/Firmware");
fixed_version = "7.5.2";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else { security_hole(0); }
}
else { exit(0, "The remote host is not affected since the remote firmware version " + version + " is installed."); }
