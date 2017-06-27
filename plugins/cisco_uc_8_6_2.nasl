#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70198);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/04/11 15:46:02 $");

  script_cve_id("CVE-2012-0367");
  script_bugtraq_id(52217);
  script_osvdb_id(79710);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtq67899");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120229-cuc");

  script_name(english:"Cisco Unity Connection Remote Denial of Service (cisco-sa-20120229-cuc)");
  script_summary(english:"Checks Cisco Unity Connection version");

  script_set_attribute(attribute:"synopsis", value:
"The version of Cisco Unity Connection on the remote host is affected by
a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"Cisco Unity Connection before 7.1.5b(Su5), 8.0, 8.5 before 8.5.1(Su3),
and 8.6 before 8.6.2 allows remote attackers to cause a denial of
service (services crash) via a series of crafted TCP segments, aka Bug
ID CSCtq67899.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120229-cuc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2a75dad4");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cisco Unity Connection 8.6.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/28");

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


if (version =~ "^7\.1(\.|$)") fix = "7.1.5.50000";
else if (version =~ "^8\.0(\.|$)") fix = "8.5.1.13900";
else if (version =~ "^8\.5(\.|$)") fix = "8.5.1.13900";
else if (version =~ "^8\.6(\.$)") fix = "8.6.2.10000";
else fix = "8.6.2.10000";

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
