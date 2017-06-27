#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70127);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/26 15:02:59 $");

  script_cve_id("CVE-2013-1133", "CVE-2013-1134");
  script_bugtraq_id(58219, 58221);
  script_osvdb_id(90679, 90680);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtx43337");
  script_xref(name:"CISCO-BUG-ID", value:"CSCub28920");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130227-cucm");

  script_name(english:"Cisco Unified Communications Manager Multiple DoS Vulnerabilities (cisco-sa-20130227-cucm)");
  script_summary(english:"Checks the version of Cisco Unified Communications Manager (CUCM).");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Cisco Unified
Communications Manager (CUCM) device is affected by one of the
following denial of service vulnerabilities :

  - A flaw exists in the in the 8.6 branch due to improper
    processing of malformed packets to unused UDP ports.
    A remote, unauthenticated attacker can cause an
    interruption of voice services and an inability to
    access the system's Graphical User Interface (GUI).
    (CVE-2013-1133 / CSCtx43337)

  - A flaw exists in the 9.0 branch due to the lack of
    authentication for Intracluster Location Bandwidth
    Manager (LBM) communication. A remote, unauthenticated
    attacker can poison LBM transaction records resulting in
    the interruption of voice services. (CVE-2013-1134 /
    CSCub28920)");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130227-cucm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d67c6687");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Unified Communications Manager 8.6(2a)su2 / 9.1(1) or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver         = get_kb_item_or_exit("Host/Cisco/CUCM/Version");
ver_display = get_kb_item_or_exit("Host/Cisco/CUCM/Version_Display");

app_name  = "Cisco Unified Communications Manager (CUCM)";
fixed_ver = NULL;
bug_id    = NULL;

if (ver =~ "^8\.6\." && ver_compare(ver:ver, fix:"8.6.2.22900.9", strict:FALSE) == -1)
{
  fixed_ver = "8.6(2a)su2";
  bug_id    = "CSCtx43337";
}
else if (ver =~ "^9\.0\.")
{
  fixed_ver = "9.1(1)";
  bug_id    = "CSCub28920";
}
else
  audit(AUDIT_INST_VER_NOT_VULN, app_name, ver_display);

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : ' + bug_id      +
    '\n  Installed release : ' + ver_display +
    '\n  Fixed release     : ' + fixed_ver   +
    '\n';

  security_hole(port:0, extra:report);
}
else security_hole(0);
