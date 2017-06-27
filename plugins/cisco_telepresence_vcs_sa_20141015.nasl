#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78625);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/03/21 19:41:17 $");

  script_cve_id("CVE-2014-3368","CVE-2014-3369","CVE-2014-3370");
  script_bugtraq_id(70589,70590,70592);
  script_osvdb_id(113378,113379,113381);
  script_xref(name:"CISCO-BUG-ID", value:"CSCui06507");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo42252");
  script_xref(name:"CISCO-BUG-ID", value:"CSCum60447");
  script_xref(name:"CISCO-BUG-ID", value:"CSCum60442");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20141015-vcs");

  script_name(english:"Cisco TelePresence VCS / Expressway Series < 8.2 Multiple DoS Vulnerabilities");
  script_summary(english:"Checks the software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by flaws that can allow a denial of
service via a device reload.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version, returned by a standard SNMP
request, the version of the Cisco TelePresence VCS or Expressway
Series device prior to 8.2. It is, therefore, potentially affected by
multiple denial of service vulnerabilities :

  - A flaw exists in packet processing when processing IP
    packets at a high rate. This can allow a remote attacker
    to cause a kernel crash via specially crafted packets.
    (CVE-2014-3368)

  - A flaw in the SIP IX Channel is triggered when handling
    a specially crafted SDP packet. This can allow a remote
    attacker to cause a system reload. SIP IX Filtering must
    be enabled for the system to be affected.
    (CVE-2014-3369)

  - A flaw exists in the SIP module that can allow a remote
    attacker to cause a system reload via a specially
    crafted SIP packet. (CVE-2014-3370)");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20141015-vcs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6ea0f5bf");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCui06507");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuo42252");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCum60447");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCum60442");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 8.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version  = get_kb_item_or_exit("Cisco/TelePresence_VCS/Version");
fullname = "Cisco TelePresence Device";

# CVRF Listed >= 5.2 and < 8.2 as affected by CVE-2014-3368
if (
  ver_compare(ver:version, fix:"5.2", strict:FALSE) >= 0 &&
  ver_compare(ver:version, fix:"8.2", strict:FALSE) <  0
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : 8.2' +
             '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_DEVICE_NOT_VULN, fullname, version);
