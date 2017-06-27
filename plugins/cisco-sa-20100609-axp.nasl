#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70164);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/05/24 02:02:50 $");

  script_cve_id( "CVE-2010-1572");
  script_bugtraq_id(40682);
  script_osvdb_id(65283);
  script_xref(name:"CISCO-BUG-ID", value:"CSCub85692");
  script_xref(name:"IAVA", value:"2010-A-0087");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20100609-axp");

  script_name(english:"Cisco Application Extension Platform (AXP) Privilege Escalation (cisco-sa-20100609-axp)");
  script_summary(english:"Check AXP model and version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running Cisco AXP, which is affected by a privilege
escalation vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Cisco Application Extension Platform (AXP) is affected by a
privilege escalation vulnerability.  The vulnerability could allow an
authenticated user to gain administrative access to a vulnerable Cisco
AXP module."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/csa/cisco-sa-20100609-axp.html");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Cisco AXP version 1.1.7 or later.  Note: Cisco AXP version
1.1.5 may or may not be vulnerable depending upon the upgrade path used. 
Installs upgraded from version 1.0 or a clean installation are not
vulnerable.  Installs upgraded from version 1.1 are vulnerable.  Refer
to the vendor's advisory for upgrade steps."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_extension_framework");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/show_software_version", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

application = "Cisco Application Extension Platform (AXP)";
showsoftware = get_kb_item_or_exit("Host/Cisco/show_software_version");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = "";

axp = egrep(pattern:"^Application eXtension Platform \(AXP\) version \([0-9.]+\).*", string:showsoftware);
if (axp)
{
  ## Application eXtension Platform (AXP) version (1.6.1)
  match =  eregmatch(pattern:".*version \(([0-9.]+)\)", string:axp);
  if (isnull(match)) exit(1, "The version of "+application+" - "+match+" - is non-numeric and, therefore, can not be used to make a determination.");
  version = match[1];
}
else audit(AUDIT_VER_FAIL, application);

notvuln = "1.0";
fixed = "1.1.6";

if (
  ver_compare(ver:version, fix:notvuln, strict:FALSE) == 0 ||
  ver_compare(ver:version, fix:fixed, strict:FALSE) >= 0
) audit(AUDIT_INST_VER_NOT_VULN, application, version);


# for 1.1 & upgraded from 1.1 to 1.1.5
report = NULL;

if (report_verbosity > 0)
{
    report =
    '\n  Installed release : ' + version +
    '\n  Fixed release     :  1.1.7 / 1.5.x' +
    '\n' +
    '\n  Note:  Users running AXP version 1.1.5 may or may not be' +
    '\n  vulnerable depending upon their upgrade path used.' +
    '\n  Those upgraded from version 1.0 or a clean installation' +
    '\n  are not vulnerable. Installs upgraded from version 1.1 are' +
    '\n  vulnerable. Refer to the vendor\'s advisory for upgrade steps.';
}
security_hole(port:0, extra:report);
