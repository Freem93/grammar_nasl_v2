#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69914);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/03/06 05:39:46 $");

  script_cve_id("CVE-2012-3063");
  script_bugtraq_id(54129);
  script_osvdb_id(83102);
  script_xref(name:"CISCO-BUG-ID", value:"CSCts30631");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120620-ace");

  script_name(english:"Cisco Application Control Engine Login Administrator IP Address Overlap (cisco-sa-20120620-ace)");
  script_summary(english:"Checks ACE version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Cisco Application Control Engine (ACE) software installed on the
remote Cisco IOS device is earlier than A4(2.3) / A5(1.1).  It,
therefore, potentially does not properly share a management IP address
among multiple contexts when multicontext mode is enabled.  This might
allow an administrative user to be logged into an unintended context
(virtual instance) on the ACE when two or more contexts are configured
with the same management IP address."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120620-ace
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?908fe0cb");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20120620-ace."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_control_engine_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
  version =~ "^A[0-3]\(" ||
  version =~ "^A4\(([01]\..+|2\.[0-2][a-z]?)\)" ||
  version =~ "^A5\((0\..+|1\.0.*)\)"
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : A4(2.3) / A5(1.1)' +
             '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ACE", version);
