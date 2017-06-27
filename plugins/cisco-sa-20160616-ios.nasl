#TRUSTED 639643a09b478b617b7060f0907dc73a1a60bf169f40b469c887eac35e5d2c3e79b7e51d7117924bd86ba2e1d525b02a7079daa3e95bde2e76e4f98a8654fe1db9bdb8d0f9886ce392443d01a6214c6ee774e7b87bdf1a86d6a53d7499d0a4a3c511b6b56eb0901d54bc4d148ee4cc269fce4b55c475afcf821e97bb22edfbb160ca2ba9a213641378b612122b1e6f87bedeead3d045621bfb9be34f394f8a3ab6ee174f9af33e14fddf18f799c3631d666adc00e27d813436337f25e41db65925e0f668eec1031e018c61d4f6244663775d7a6fd1217fbb31789043827435e62f2fac8b90c3d919694821b3837c6f1fb8d43f3a4f13b2192c34f73ba0d7ee9c18b9082dfc626077ff8673573ba3c882bf5a3fe1207aa0499dd8327448648903e6e93b86ffb70605cb40c43c0368f06c78c7133e215e81a42c2a10531a413f63e1fc67c9a1ba80b1eed324457c6aa5281036c9fee33006bdfe22168de0f2798748a27136729b3753f4f4a486300bdcd926eb281fb1be5a5646ad4467f0ed6cf7e7d448a1eb97adfe7cf63dd72f466f960f99de92ce8a1cfcaaf131161ee2ac38759a3923e1a90809f07ad441e36e06c081e0488cd2b38a701982a2b4cb79e7e66a51d6b5d2ece78d763f9577c4869307bdf32941deec04392e8f651f41741f3c48109c080a609a484035bef5d61343f1ca9635deb9bda8d6d9ab9edbf7acb661
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91761);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/06/22");

  script_cve_id("CVE-2016-1424");
  script_osvdb_id(140208);
  script_xref(name:"CISCO-BUG-ID", value:"CSCun63132");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160616-ios");

  script_name(english:"Cisco IOS LLDP Packet Handling Remote DoS (cisco-sa-20160616-ios)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported IOS version, the remote device is
affected by a denial of service vulnerability in the Link Layer
Discovery Protocol (LLDP) packet processing code due to improper
handling of malformed LLDP packets. An unauthenticated, adjacent
attacker can exploit this, via specially crafted LLDP packets, to
crash the device, resulting in a denial of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160616-ios
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?810513a2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCun63132.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Check for vuln version
if ( ver == '15.2(1)T1.11' ) flag++;
if ( ver == '15.2(2)TST' ) flag++;

# LLDP check
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ntp_status", "show LLDP");
  if (check_cisco_result(buf))
  {
    if (
      "% LLDP is not enabled" >< buf &&
      "ACTIVE" >!< buf
    ) audit(AUDIT_HOST_NOT, "affected because LLDP is not enabled");
  }
  else if (cisco_needs_enable(buf)) override = 1;
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCun63132' +
      '\n  Installed release : ' + ver +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS software", ver);
