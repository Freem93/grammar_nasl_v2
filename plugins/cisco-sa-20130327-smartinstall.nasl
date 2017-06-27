#TRUSTED 8bf2839d7b31fa5c5714e2e59116b6d910ff69fc2203c2160c12cf270928cc5877fe749a72986a4ada5c63e3916966313d088339686dd21ffb89638f94b40c6076c082aeb4af9123a060997b6e19eb2b608c2d5ed01f44e32754b746d717e261588c7771d2d12f9c47d45823c87ef5d805605f283babf64b101bfc95e1969688c24500e5ac408d822fdc0c5dce0e74e9f9d0cd27c6111725663d44939c25b39bd28bfb5d070f7f9a365a588dc5cf23d0c17487d1bdfed571c8c1b54f613a79e0e38f9afba5de6e4246e768ae7a81327ce8c4338d86bab7bccda381a441efe1e55856278d1e8ae6fffe776c30cb77ddcb54f9344ea9a9e4c7ac95f9c512a31b67bc5321132fa762b667e5c721367af70f0aa8a97db226d1f3bc1c3c6cec7b72e4edeca49ab10710c8cef7de23c020dbc2c1b597c80ddccb88148d402ff87ba1ef3506c7a6c298022e370dc9070c8ea7b699ed401f835502af15ec4d86c8e7c80a0154aa201df7d00e05b7ae6f0b12c0f0fe6ec989d4682a58eb40362083600f9d85f00a23af32d2fd744f4d126213072b94e450bc45f624161f4a58bc420e5d50767c39d7eef6af2d0dc6eb6690b121d0d97b593d2b8a2e747559503bc9447da00ee363b6bdd56ac6d1b793324565bfa2c47d282036dc77a42cc140e0752ded0e00f58b6328c10c48b368947267d3497b311f7ddfea27dacda90289d9974266b1
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130327-smartinstall.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(65891);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/10/07");

  script_cve_id("CVE-2013-1146");
  script_bugtraq_id(58746);
  script_osvdb_id(91760);
  script_xref(name:"TRA", value:"TRA-2013-03");
  script_xref(name:"CISCO-BUG-ID", value:"CSCub55790");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130327-smartinstall");

  script_name(english:"Cisco IOS Software Smart Install Denial of Service Vulnerability (cisco-sa-20130327-smartinstall)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Smart Install client feature in Cisco IOS Software contains a
vulnerability that could allow an unauthenticated, remote attacker to
cause a denial of service (DoS) condition on an affected device.
Affected devices that are configured as Smart Install clients are
vulnerable. Cisco has released free software updates that address this
vulnerability. There are no workarounds for devices that have the
Smart Install client feature enabled."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2013-03");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130327-smartinstall
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?72f23000"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130327-smartinstall."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
if ( version == '12.2(55)EX' ) flag++;
if ( version == '12.2(55)EX1' ) flag++;
if ( version == '12.2(55)EX2' ) flag++;
if ( version == '12.2(55)EX3' ) flag++;
if ( version == '12.2(55)EY' ) flag++;
if ( version == '12.2(55)EZ' ) flag++;
if ( version == '12.2(55)SE' ) flag++;
if ( version == '12.2(55)SE1' ) flag++;
if ( version == '12.2(55)SE2' ) flag++;
if ( version == '12.2(55)SE3' ) flag++;
if ( version == '12.2(55)SE4' ) flag++;
if ( version == '12.2(55)SE5' ) flag++;
if ( version == '12.2(55)SE6' ) flag++;
if ( version == '12.2(58)EX' ) flag++;
if ( version == '12.2(58)EY' ) flag++;
if ( version == '12.2(58)EY1' ) flag++;
if ( version == '12.2(58)EY2' ) flag++;
if ( version == '12.2(58)EZ' ) flag++;
if ( version == '12.2(58)SE' ) flag++;
if ( version == '12.2(58)SE1' ) flag++;
if ( version == '12.2(58)SE2' ) flag++;
if ( version == '15.0(1)EY' ) flag++;
if ( version == '15.0(1)EY1' ) flag++;
if ( version == '15.0(1)EY2' ) flag++;
if ( version == '15.0(1)SE' ) flag++;
if ( version == '15.0(1)SE1' ) flag++;
if ( version == '15.0(1)SE2' ) flag++;
if ( version == '15.0(1)SE3' ) flag++;
if ( version == '15.0(2)SE' ) flag++;
if ( version == '15.1(1)SG' ) flag++;
if ( version == '15.1(1)SG1' ) flag++;
if ( version == '15.1(1)SG2' ) flag++;
if ( version == '15.1(1)SY' ) flag++;
if ( version == '15.1(4)GC' ) flag++;
if ( version == '15.2(1)GC' ) flag++;
if ( version == '15.2(1)GC1' ) flag++;
if ( version == '15.2(1)GC2' ) flag++;
if ( version == '15.2(2)GC' ) flag++;
if ( version == '15.2(3)GC' ) flag++;
if ( version == '15.2(3)GCA' ) flag++;
if ( version == '15.2(3)XA' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_vstack_config", "show vstack config");
    if (check_cisco_result(buf))
    {
      if ( (preg(multiline:TRUE, pattern:"Role:\s*[Cc]lient", string:buf)) &&
         (!preg(multiline:TRUE, pattern:"Role:\s*[Cc]lient\s+\(SmartInstall disabled\)", string:buf)) ) { flag = 1; }
    }
    else if (cisco_needs_enable(buf)) {flag = 1; override = 1; }
  }
}

if (flag)
{
  report +=
    '\n  Cisco Bug ID        : CSCub55790' +
    '\n    Installed release : ' + version + '/n';
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
