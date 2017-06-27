#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70197);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/04/11 15:46:02 $");

  script_cve_id("CVE-2012-0366");
  script_bugtraq_id(52216);
  script_osvdb_id(79709);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtd45141");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120229-cuc");

  script_name(english:"Cisco Unity Connection Administrator Password Bypass (cisco-sa-20120229-cuc)");
  script_summary(english:"Checks Cisco Unity Connection Version.");

  script_set_attribute(attribute:"synopsis", value:
"Cisco Unity Connection is installed on the remote host and is affected
by a password bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"Cisco Unity Connection before 7.1.3b(Su2) / 7.1.5 allows remote,
authenticated users to change the administrative password by leveraging
the Help Desk Administrator role, aka Bug ID CSCtd45141.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120229-cuc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2a75dad4");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cisco Unity Connection 7.1.3b / 7.1.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/28");
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unity_connection");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_uc_version.nasl");
  script_require_keys("Host/Cisco/Unity_Connection/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item("Host/Cisco/Unity_Connection/Version");
if (isnull(version)) audit(AUDIT_NOT_INST, 'Cisco Unity Connection');

if (version =~ "^7\.1\.3(\.|$)") fix = "7.1.3.30000";
else if (version =~ "^7\.1\.5(\.|$)") fix = "7.1.5.50000";
else fix = "7.1.5.50000";

ver = str_replace(find:"-", replace:".", string:ver);
fix = str_replace(find:"-", replace:".", string:fix);

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + 
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco Unity Connection", version);
