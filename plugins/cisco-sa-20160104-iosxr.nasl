#TRUSTED 200a3ad40c31aafb3232710fc029b864aa6913a7f29e2bb05dfc89de844ff9b79274ee857b01b5b2c7f20c63d34a2e5fe3e06fd181d858ceb155e336a9e968077baa097dd1cc985de169c2c6159633b386ace6f90a3aa48fa2da4f7fb6cc89cc3e06c5a4b92122eba0d9b56b20681908e22b4e0a1642b928ffecc572c21ab04f38226f68ffd67a5407130c1d5f2cec55008da60f0018f438ff625d35ce8c0b9420ddf500a5ba3b3fc66380506ffec8c6c104323e586626dad4772a43728bc3e3f22d52ef8cd8cc3bd469c5dc6232938a497fcfc955ac1db681e96e493a83581d0304dc5f330f337bfc1c1e81e4c330a547fcd23f578cede305457e46c57140b7c05c983615b4d1ea7f96696471e4864c507c1f6acbee8c6f0410b3a987c7e8254aa8db3fe188d851fc7aff6914b9c787bfcff8c1c8c45872e6de3849ecfed4fc0e24215cef47866ff3ad9266f21d598edc7d720f0c47ffc43cc77f70c33020f24850db46c15d3ef5cdb6a4f03ad98cf0bde73c5bd96c1addd477e974624a51689ba21ef2284fb9f6fc23fd2e2254e6fa90e59393483b444dda0d2fad7c143e5109d4693c4af527a23594d8d68f326cffda5acaec84c42a3000897ebf14be67d9927aa49f7bcafa6bbd7c251e0b98c3d3e3ab78eddf33bd6aead99e4bd3020e245bb526e7117930fe146ce3c9278865203b4de15f145bb898692240c46731ea38
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87819);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/08/24");

  script_cve_id("CVE-2015-6432");
  script_bugtraq_id(79831);
  script_osvdb_id(132517);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw83486");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160104-iosxr");

  script_name(english:"Cisco IOS XR OSPF Link State Advertisement PCE DoS (cisco-sa-20160104-iosxr)");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XR device is affected by a denial of service
vulnerability due to the number of Open Shortest Path First (OSPF)
Path Computation Elements (PCEs) configured for the OSPF Link State
Advertisement (LSA) opaque area update. An unauthenticated, remote
attacker can exploit this, via a specially crafted OSPF LSA update, to
cause a denial of service condition.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160104-iosxr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c76d98ff");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20160104-iosxr.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");
  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

cbi = "CSCuw83486";

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");

if( version =~ '^4\\.[23]\\.0([^0-9]|$)' ) flag = 1;
if( version =~ '^5\\.[0-3]\\.0([^0-9]|$)' ) flag = 1;
if( version =~ '^5\\.2\\.[24]([^0-9]|$)' ) flag = 1;
if( version == '5.3.2' ) flag = 1;

if (get_kb_item("Host/local_checks_enabled") && flag)
{
  flag = 0;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if( preg(multiline:TRUE, pattern:"^pce ", string:buf))
      flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : ' + cbi +
      '\n  Installed release : ' + version +
      '\n';

    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
