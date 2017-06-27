#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72183);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id("CVE-2014-0661");
  script_bugtraq_id(65071);
  script_osvdb_id(102362);
  script_xref(name:"CISCO-BUG-ID", value:"CSCui32796");
  script_xref(name:"IAVA", value:"2014-A-0016");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140122-cts");

  script_name(english:"Cisco TelePresence System Software Command Execution");
  script_summary(english:"Checks for software presence.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote device may be affected by a command execution
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the self-reported device name of the remote device, it may
be a Cisco TelePresence System device. Nessus cannot determine the
version of the software running on this device, but it may be affected
by a vulnerability that could allow an unauthorized user to execute
arbitrary commands via a specially crafted XML remote procedure call."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140122-cts
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6c63336a");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=32461");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the appropriate software version per the vendor's
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_system_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_system_detect.nbin");
  script_require_keys("Settings/ParanoidReport", "Cisco/TelePresence_System/Version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = get_kb_item_or_exit("Cisco/TelePresence_System/Version");

if (report_verbosity > 0)
{
  report = '\n  Nessus was unable to detect the exact version of Cisco' +
           '\n  TelePresence System software.\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
