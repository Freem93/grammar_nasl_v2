#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97326);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/27 15:13:22 $");

  script_cve_id("CVE-2017-3790");
  script_bugtraq_id(95786);
  script_osvdb_id(150928);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus99263");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170125-expressway");
  script_xref(name:"IAVA", value:"2017-A-0041");

  script_name(english:"Cisco TelePresence VCS / Expressway < 8.8.2 Received Packet Parser DoS");
  script_summary(english:"Checks the software version.");

  script_set_attribute(attribute:"synopsis", value:
"A video conferencing application running on the remote host is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco TelePresence Video
Communication Server (VCS) / Expressway running on the remote host is
prior to 8.8.2. It is, therefore, affected by a denial of service
vulnerability in the received packet parser due to insufficient size
validation of user-supplied input. An unauthenticated, remote attacker
can exploit this, via specially crafted H.224 data in Real-Time
Transport Protocol (RTP) packets, to cause a buffer overflow in the
cache, resulting in crashing the application and a system reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170125-expressway
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2cc3432");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCus99263");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2017/Jan/72");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco TelePresence VCS / Expressway version 8.8.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:expressway_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("global_settings.inc");
include("misc_func.inc");

version  = get_kb_item_or_exit("Cisco/TelePresence_VCS/Version");
fullname = "Cisco TelePresence Device";
fix = '8.8.2';
bug_id = 'CSCus99263';

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  security_report_cisco(severity:SECURITY_HOLE, port:0,  version:version, fix:fix, bug_id:bug_id);
}
else audit(AUDIT_DEVICE_NOT_VULN, fullname, version);
