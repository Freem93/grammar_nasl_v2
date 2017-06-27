#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87849);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/28 18:15:08 $");

  script_cve_id("CVE-2015-6426");
  script_bugtraq_id(79582);
  script_osvdb_id(132035);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus99427");
  script_xref(name:"IAVA", value:"2016-A-0003");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151217-pnsc");

  script_name(english:"Cisco Prime Network Services Controller Unauthorized Local Command Execution (cisco-sa-20151217-pnsc)");
  script_summary(english:"Check the version of NSC.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Cisco Prime NSC device is affected by a local command
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Cisco Prime Network Services Controller (NSC)
running on the remote host is in the 3.0 release branch. It is,
therefore, affected by a local command execution vulnerability due to
improper validation of user-supplied input when handling extra
parameters for certain local commands. A local attacker can exploit
this to execute arbitrary commands.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151217-pnsc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?498017a6");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCus99427");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Prime Network Services Controller version 4.0 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_network_services_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/Prime NSC/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/Cisco/Prime NSC/version");
source = get_kb_item_or_exit("Host/Cisco/Prime NSC/source");

if (version =~ "^3\.0([^0-9]|$)")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Source  : ' + source +
      '\n  Version : ' + version +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_HOST_NOT, "affected");
