#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77968);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/27 16:08:35 $");

  script_cve_id("CVE-2014-3292");
  script_bugtraq_id(67982);
  script_osvdb_id(107848);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo17199");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo17302");

  script_name(english:"Cisco Unified Communications Manager Multiple Arbitrary File Manipulation Vulnerabilities (CSCuo17199 / CSCuo17302)");
  script_summary(english:"Checks the version of Cisco Unified Communications Manager (CUCM).");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple file manipulation
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Cisco Unified
Communications Manager (CUCM) device is affected by multiple file
manipulation vulnerabilities in the Real-Time Monitoring Tool (RTMT)
due to improper validation of user-supplied input. An authenticated,
remote attacker can exploit these vulnerabilities, via a specially
crafted HTTP request, to read or delete arbitrary files.

Note that because this vulnerability is considered moderate severity
by the vendor, the existing version check information may not be
complete. For additional verification, please contact TAC Cisco
support.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-3292
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31d6f89d");
  # http://www.cisco.com/c/en/us/about/security-center/security-vulnerability-policy.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5517c0f");
  # http://www.cisco.com/c/en/us/support/web/tsd-cisco-worldwide-contacts.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e13eb27");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCuo17199 and CSCuo17302. Please contact TAC Cisco support for
additional information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");
  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

ver         = get_kb_item_or_exit("Host/Cisco/CUCM/Version");
ver_display = get_kb_item_or_exit("Host/Cisco/CUCM/Version_Display");

app_name  = "Cisco Unified Communications Manager (CUCM)";

# 10.0(1.10000.99) is the only known affected release
if (ver != "10.0.1.10000.99")
  audit(AUDIT_INST_VER_NOT_VULN, app_name, ver_display);

fixed_ver = "10.5.2.10000-5 / 11.0.0.98100-18 / 11.5.0.98000-126";

security_report_cisco(
  port:0,
  severity:SECURITY_WARNING,
  bug_id:"CSCuo17199 / CSCuo17302",
  version:ver_display,
  fix:fixed_ver
);
