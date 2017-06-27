#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92948);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2016-1456");
  script_bugtraq_id(91785);
  script_osvdb_id(141501);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160714-ios-xr");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz62721");

  script_name(english:"Cisco IOS XR 6.0.1.x and 6.0.2.x < 6.0.2.7 / 6.1.x < 6.1.1.17 Command Input Handling Privilege Escalation");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco IOS XR running on the remote device is 6.0.1.x
or 6.0.2.x prior to 6.0.2.7, or 6.1.x prior to 6.1.1.17. It is,
therefore, affected by a privilege escalation vulnerability in the
command-line utility due to improper validation of user-supplied
input. A local attacker can exploit this, via crafted input to a
command within a specific container, to execute arbitrary commands
with root privileges.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160714-ios-xr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a11b991");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz62721");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuz62721.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Cisco IOS XR";

# Check model
# per Cisco Business Unit :
# - "This impacts NCS5500/NCS1K series only."
#   "NCS4K, NCS6K, CRS or ASR9K series are not impacted."

model = get_kb_item("CISCO/model");

if (model)
{
  if (model !~ "^cisco([Nn]cs|NCS)(5500|1k)")
    audit(AUDIT_HOST_NOT, "an affected model");
}
else
{
  model = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");
  if ("NCS5500" >!< model && "NCS1K" >!< model)
    audit(AUDIT_HOST_NOT, "an affected model");
}

# Check version

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");

if ( version =~ "^6\.0\.[12]\." ) fix = "6.0.2.7";
else if ( version =~ "^6\.1\." ) fix = "6.1.1.17";
else audit(AUDIT_HOST_NOT, app_name + "6.0.1.x / 6.0.2.x / 6.1.x");

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Cisco bug ID      : CSCuz62721' +
    '\n  Installed release : ' + version +
    '\n  Fixed release     : ' + fix;
  report += '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
