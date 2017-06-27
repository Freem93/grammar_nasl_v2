#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83773);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/03 20:48:28 $");

  script_cve_id("CVE-2015-0713");
  script_bugtraq_id(74638);
  script_osvdb_id(122101);
  script_xref(name:"CISCO-BUG-ID", value:"CSCur08993");
  script_xref(name:"IAVA", value:"2015-A-0117");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150513-tp");

  script_name(english:"Cisco TelePresence Server Command Injection Vulnerability");
  script_summary(english:"Checks the software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version, the remote Cisco TelePresence
Server contains a vulnerability in its web framework, which can allow
an authenticated, remote attacker to inject arbitrary commands on the
device with root permissions.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150513-tp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3bd0b238");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCur08993");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the appropriate software version referenced in the
vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_server_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_server_detect.nasl");
  script_require_keys("Cisco/TelePresence_Server/Version", "Cisco/TelePresence_Server/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

model    = get_kb_item_or_exit("Cisco/TelePresence_Server/Model");
version  = get_kb_item_or_exit("Cisco/TelePresence_Server/Version");
fullname = "Cisco TelePresence " + model;

if (model == "Virtual Machine") fix = '4.1(1.79)';
else fix = '3.1(1.98)';

if (cisco_gen_ver_compare(a:version, b:fix) == -1)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : ' + fix +
             '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco TelePresence Server software");
