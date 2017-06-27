#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69789);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/09/18 16:18:02 $");

  script_cve_id("CVE-2013-1177");
  script_bugtraq_id(59271);
  script_osvdb_id(92512);
  script_xref(name:"CISCO-BUG-ID", value:"CSCub23095");
  script_xref(name:"IAVA", value:"2013-A-0095");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130417-nac");

  script_name(english:"Cisco Network Admission Control Manager SQL Injection (cisco-sa-20130417-nac)");
  script_summary(english:"Checks the NAC version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Cisco Network Admission Control (NAC) Manager may be
affected by a SQL injection vulnerability.  This vulnerability could
allow an unauthenticated, remote attacker to take full control of the
system (i.e.  access, create or modify any information in the NAC
Manager database)."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130417-nac
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97ea34b2");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130417-nac."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:network_admission_control_manager_and_server_system_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/05");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_nac_version.nasl");
  script_require_keys("Host/Cisco/NAC/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

version = get_kb_item_or_exit("Host/Cisco/NAC/Version");

flag = 0;
fixed_version = "";

if (ver_compare(ver:version, fix:"4.8.3.1", strict:FALSE) == -1)
{
  flag++;
  fixed_version = "4.8.3.1 or 4.9.2";
}

if ((ver_compare(ver:version, fix:"4.9", strict:FALSE) >= 0 ) && (ver_compare(ver:version, fix:"4.9.2", strict:FALSE) == -1))
{
  flag++;
  fixed_version = "4.9.2";
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed Version : ' + version +
      '\n  Fixed version     : ' + fixed_version;
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
