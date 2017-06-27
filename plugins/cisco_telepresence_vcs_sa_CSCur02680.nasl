#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81974);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/24 14:57:04 $");

  script_cve_id("CVE-2015-0653");
  script_bugtraq_id(73044);
  script_osvdb_id(119448);
  script_xref(name:"CISCO-BUG-ID", value:"CSCur02680");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150311-vcs");

  script_name(english:"Cisco TelePresence VCS / Expressway Series < 7.2.4 / 8.1.2 / 8.2.2 Login Security Bypass Vulnerability");
  script_summary(english:"Checks the software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Cisco TelePresence
VCS or Expressway Series on the remote host contains an vulnerability
due to inadequate validation of parameters passed during the login
process. A remote attacker, using a crafted request and knowledge of a
valid user name, can bypass authentication requirements and login to
the system.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCur02680");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150311-vcs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dcf7f93e");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 7.2.4 / 8.1.2 / 8.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:expressway_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version  = get_kb_item_or_exit("Cisco/TelePresence_VCS/Version");
fullname = "Cisco TelePresence Device";

# CVRF and Alert listed >= 5.2 and < 8.1.2 and
# 8.2.x < 8.2.1 as affected by CVE-2015-0653
if (
  ver_compare(ver:version, fix:"5.2", strict:FALSE) >= 0 &&
  ver_compare(ver:version, fix:"7.2.4", strict:FALSE) <  0
)
  fix = '7.2.4';
else if
(
  version =~ "^8\.1($|[^0-9])" &&
  ver_compare(ver:version, fix:"8.1.2", strict:FALSE) <  0
)
  fix = '8.1.2';
else if
(
  version =~ "^8\.2($|[^0-9])" &&
  ver_compare(ver:version, fix:"8.2.2", strict:FALSE) <  0
)
  fix = '8.2.2';
else
  audit(AUDIT_DEVICE_NOT_VULN, fullname, version);

if (report_verbosity > 0)
{
  report = '\n  Installed version : ' + version +
           '\n  Fixed version     : ' + fix +
           '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
