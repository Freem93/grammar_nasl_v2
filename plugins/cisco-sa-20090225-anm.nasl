#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69913);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/09/19 02:37:44 $");

  script_cve_id("CVE-2009-0615");
  script_bugtraq_id(33903);
  script_osvdb_id(52376);
  script_xref(name:"CISCO-BUG-ID", value:"CSCsv66063");
  script_xref(name:"IAVT", value:"2009-T-0016");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20090225-anm");

  script_name(english:"Cisco Application Control Engine < A3(2.1) Multiple Unspecified Traversals (cisco-sa-20090225-anm)");
  script_summary(english:"Checks ACE version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Cisco Application Control Engine (ACE) software installed on the
remote Cisco IOS device is earlier than A3(2.1).  It is, therefore,
potentially affected by multiple unspecified directory traversals.
An authenticated attacker could exploit these to access ACE operating
system and host operating system files."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/csa/cisco-sa-20090225-anm.html");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Cisco ACE A3(2.1) or later as discussed in Cisco Security
Advisory cisco-sa-20090225-anm."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_control_engine_device_manager");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/16");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ace_version.nasl");
  script_require_keys("Host/Cisco/ACE/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");


version = get_kb_item("Host/Cisco/ACE/Version");
if (isnull(version)) audit(AUDIT_NOT_INST, 'Cisco ACE');


if (
  version =~ "^A[0-2]\(" ||
  version =~ "^A3\(([01]\..+|2\.0)\)"
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : A3(2.1)' +
             '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ACE", version);
