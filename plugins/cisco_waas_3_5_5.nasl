#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71841);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/01/07 17:27:38 $");

  script_cve_id("CVE-2013-5554");
  script_bugtraq_id(63554);
  script_osvdb_id(99490);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh69773");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20131106-waasm");

  script_name(english:"Cisco WAAS Mobile Server < 3.5.5 Remote Code Execution");
  script_summary(english:"Checks Cisco WAAS Mobile version");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by a remote code
execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of Cisco WAAS Mobile Server prior to
version 3.5.5.  It is, therefore, affected by a remote code execution
vulnerability that can be triggered via a specially crafted HTTP POST
request with a directory traversal string to the ReportReceiver."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-276/");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20131106-waasm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?caf35c60");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cisco WAAS Mobile Server 3.5.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:wide_area_application_services_mobile");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("cisco_waas_mobile_installed.nbin");
  script_require_keys("SMB/Cisco_WAAS_Mobile_Server/Installed");
  exit(0);

}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "SMB/Cisco_WAAS_Mobile_Server/";
get_kb_item_or_exit(kb_base + "Installed");
num_installs = get_kb_item_or_exit(kb_base + "NumInstalls");

report = "";
for (install_num = 0; install_num < num_installs; install_num++)
{
  version = get_kb_item(kb_base + install_num + "/Version");
  if (!isnull(version) && ver_compare(ver:version, fix:'3.5.5', strict:FALSE) == -1)
  {
    path = get_kb_item(kb_base + install_num + "/Path");
    report += '\n  Path              : ' + path +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : 3.5.5\n';
  }
}

if (report)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0) security_hole(port:port, extra:report);
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco WAAS Mobile Server");
