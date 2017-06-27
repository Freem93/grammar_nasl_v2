#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81953);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/24 14:57:04 $");

  script_cve_id("CVE-2015-0652");
  script_bugtraq_id(73047);
  script_osvdb_id(119447);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus96593");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150311-vcs");

  script_name(english:"Cisco TelePresence VCS / Expressway Series < 8.2 SDP Media Description Vulnerability");
  script_summary(english:"Checks the software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version, the Cisco TelePresence VCS or
Expressway Series on the remote host contains an vulnerability related
to the Session Description Protocol (SDP) packet handler function. A
remote, unauthenticated attacker, using a crafted SDP packet to
trigger a reload, can exploit this to cause a denial.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCus96593");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150311-vcs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dcf7f93e");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 8.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
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

# CVRF and Alert listed >= 5.2 and < 8.2 as affected by CVE-2015-0652
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
