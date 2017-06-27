#TRUSTED 7bd9d2e27edc96deb0441d84596d4a92a00d334f1a3aa1bd1551cd2f2d614d9f7bcb9010b1cad53f2fcd0196caece44b760690f8103b48ec24b610b795f544a78d0edd42bacf7b4252299eccf8432af3f6d43689455f66234494c7b7aad58647dfd8b0e039406ba53b098d4132c4086af8d32a7322ed2c950b0efbbff69cfadef54c9ce635d121996fb16c23b012932fd46fc93b4ac7d47ad7c2e97ad28d80cd37474674d9fd26114fcb3cdcab736bfef1e4cb74a61ac16ded8f5dc5c0cfb318786bb5bbc83a78510a4fa536cd2a09ce2751f2edf148c698cf7be3eb759bad727651f68eb6b8159198760c00522858c06632c4358887ab60ca6dc5c8ab76abd7a155a592040532b98bd05e497b23b5989d83e7cf665a8fea67adc7c6b23030c241f18261a766a9df5b4e77fcdf707105b267dd80087cd52412135a44897c6770748103b2cfeaace1ea71bd448c0682b1d29d6dd5d3e884ace657f0ba7468037c7c20a5ca7c82513170162cdd5390b8344ab0b20ed0725e2a6cf975c85180a08c2ac8628862fc8d1eb7464d5b7d07687acce05ee5cb3348e75ce08e47ad0c9f9e66e1a2e70a82d5049623c7693c967a8c9a1e5a7b777a95e04066dbea3ae411b6a8a743bfabb0abc542717b51a8bdc6b604473391b32442612311a8caf0fc049ae7c028ce108b0c4e6693ed6ce5a5ed080480cbb07b2afc554aaeab275eceea50
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90355);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/14");

  script_cve_id("CVE-2016-1344");
  script_osvdb_id(136250);
  script_xref(name:"TRA", value:"TRA-2016-06");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux38417");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-ios-ikev2");

  script_name(english:"Cisco IOS IKEv2 Fragmentation DoS (cisco-sa-20160323-ios-ikev2)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by a denial of service vulnerability
in the Internet Key Exchange version 2 (IKEv2) subsystem due to
improper handling of fragmented IKEv2 packets. An unauthenticated,
remote attacker can exploit this issue, via specially crafted UDP
packets, to cause the device to reload.

Note that this issue only affects devices with IKEv2 fragmentation
enabled and is configured for any VPN type based on IKEv2.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-ios-ikev2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea61d7e9");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2016-06");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCux38417. Alternatively, apply the workaround as referenced in the
vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Check for vuln version
if ( ver == '15.0(2)ED' ) flag++;
if ( ver == '15.0(2)ED1' ) flag++;
if ( ver == '15.0(2)EH' ) flag++;
if ( ver == '15.0(2)EJ' ) flag++;
if ( ver == '15.0(2)EJ1' ) flag++;
if ( ver == '15.0(2)EK' ) flag++;
if ( ver == '15.0(2)EK1' ) flag++;
if ( ver == '15.0(2)EX' ) flag++;
if ( ver == '15.0(2)EX1' ) flag++;
if ( ver == '15.0(2)EX3' ) flag++;
if ( ver == '15.0(2)EX4' ) flag++;
if ( ver == '15.0(2)EX5' ) flag++;
if ( ver == '15.0(2a)EX5' ) flag++;
if ( ver == '15.0(2)EY' ) flag++;
if ( ver == '15.0(2)EY1' ) flag++;
if ( ver == '15.0(2)EY3' ) flag++;
if ( ver == '15.0(2)EZ' ) flag++;
if ( ver == '15.0(2)SE' ) flag++;
if ( ver == '15.0(2)SE1' ) flag++;
if ( ver == '15.0(2)SE2' ) flag++;
if ( ver == '15.0(2)SE3' ) flag++;
if ( ver == '15.0(2)SE4' ) flag++;
if ( ver == '15.0(2)SE5' ) flag++;
if ( ver == '15.0(2)SE6' ) flag++;
if ( ver == '15.0(2)SE7' ) flag++;
if ( ver == '15.0(2)SE8' ) flag++;
if ( ver == '15.0(2)SE9' ) flag++;
if ( ver == '15.0(2a)SE9' ) flag++;
if ( ver == '15.1(4)GC' ) flag++;
if ( ver == '15.1(4)GC1' ) flag++;
if ( ver == '15.1(4)GC2' ) flag++;
if ( ver == '15.1(4)M' ) flag++;
if ( ver == '15.1(4)M1' ) flag++;
if ( ver == '15.1(4)M10' ) flag++;
if ( ver == '15.1(4)M2' ) flag++;
if ( ver == '15.1(4)M3' ) flag++;
if ( ver == '15.1(4)M3a' ) flag++;
if ( ver == '15.1(4)M4' ) flag++;
if ( ver == '15.1(4)M5' ) flag++;
if ( ver == '15.1(4)M6' ) flag++;
if ( ver == '15.1(4)M7' ) flag++;
if ( ver == '15.1(4)M8' ) flag++;
if ( ver == '15.1(4)M9' ) flag++;
if ( ver == '15.1(3)MR' ) flag++;
if ( ver == '15.1(3)MRA' ) flag++;
if ( ver == '15.1(3)MRA1' ) flag++;
if ( ver == '15.1(3)MRA2' ) flag++;
if ( ver == '15.1(3)MRA3' ) flag++;
if ( ver == '15.1(3)MRA4' ) flag++;
if ( ver == '15.1(2)S' ) flag++;
if ( ver == '15.1(2)S1' ) flag++;
if ( ver == '15.1(2)S2' ) flag++;
if ( ver == '15.1(3)S' ) flag++;
if ( ver == '15.1(3)S0a' ) flag++;
if ( ver == '15.1(3)S1' ) flag++;
if ( ver == '15.1(3)S2' ) flag++;
if ( ver == '15.1(3)S3' ) flag++;
if ( ver == '15.1(3)S4' ) flag++;
if ( ver == '15.1(3)S5' ) flag++;
if ( ver == '15.1(3)S5a' ) flag++;
if ( ver == '15.1(3)S6' ) flag++;
if ( ver == '15.1(1)SG' ) flag++;
if ( ver == '15.1(1)SG1' ) flag++;
if ( ver == '15.1(1)SG2' ) flag++;
if ( ver == '15.1(2)SG' ) flag++;
if ( ver == '15.1(2)SG1' ) flag++;
if ( ver == '15.1(2)SG2' ) flag++;
if ( ver == '15.1(2)SG3' ) flag++;
if ( ver == '15.1(2)SG4' ) flag++;
if ( ver == '15.1(2)SG5' ) flag++;
if ( ver == '15.1(2)SG6' ) flag++;
if ( ver == '15.1(2)SG7' ) flag++;
if ( ver == '15.1(2)SNG' ) flag++;
if ( ver == '15.1(2)SNH' ) flag++;
if ( ver == '15.1(2)SNI' ) flag++;
if ( ver == '15.1(2)SNI1' ) flag++;
if ( ver == '15.1(1)SY' ) flag++;
if ( ver == '15.1(1)SY1' ) flag++;
if ( ver == '15.1(1)SY2' ) flag++;
if ( ver == '15.1(1)SY3' ) flag++;
if ( ver == '15.1(1)SY4' ) flag++;
if ( ver == '15.1(1)SY5' ) flag++;
if ( ver == '15.1(1)SY6' ) flag++;
if ( ver == '15.1(2)SY' ) flag++;
if ( ver == '15.1(2)SY1' ) flag++;
if ( ver == '15.1(2)SY2' ) flag++;
if ( ver == '15.1(2)SY3' ) flag++;
if ( ver == '15.1(2)SY4' ) flag++;
if ( ver == '15.1(2)SY4a' ) flag++;
if ( ver == '15.1(2)SY5' ) flag++;
if ( ver == '15.1(2)SY6' ) flag++;
if ( ver == '15.1(3)T' ) flag++;
if ( ver == '15.1(3)T1' ) flag++;
if ( ver == '15.1(3)T2' ) flag++;
if ( ver == '15.1(3)T3' ) flag++;
if ( ver == '15.1(3)T4' ) flag++;
if ( ver == '15.2(1)E' ) flag++;
if ( ver == '15.2(1)E1' ) flag++;
if ( ver == '15.2(1)E2' ) flag++;
if ( ver == '15.2(1)E3' ) flag++;
if ( ver == '15.2(2)E' ) flag++;
if ( ver == '15.2(2)E1' ) flag++;
if ( ver == '15.2(2)E2' ) flag++;
if ( ver == '15.2(2)E3' ) flag++;
if ( ver == '15.2(2a)E1' ) flag++;
if ( ver == '15.2(2a)E2' ) flag++;
if ( ver == '15.2(3)E' ) flag++;
if ( ver == '15.2(3)E1' ) flag++;
if ( ver == '15.2(3)E2' ) flag++;
if ( ver == '15.2(3)E3' ) flag++;
if ( ver == '15.2(3a)E' ) flag++;
if ( ver == '15.2(3m)E2' ) flag++;
if ( ver == '15.2(4)E' ) flag++;
if ( ver == '15.2(4)E1' ) flag++;
if ( ver == '15.2(2)EB' ) flag++;
if ( ver == '15.2(2)EB1' ) flag++;
if ( ver == '15.2(1)EY' ) flag++;
if ( ver == '15.2(2)EA1' ) flag++;
if ( ver == '15.2(2)EA2' ) flag++;
if ( ver == '15.2(3)EA' ) flag++;
if ( ver == '15.2(4)EA' ) flag++;
if ( ver == '15.2(1)GC' ) flag++;
if ( ver == '15.2(1)GC1' ) flag++;
if ( ver == '15.2(1)GC2' ) flag++;
if ( ver == '15.2(2)GC' ) flag++;
if ( ver == '15.2(3)GC' ) flag++;
if ( ver == '15.2(3)GC1' ) flag++;
if ( ver == '15.2(4)GC' ) flag++;
if ( ver == '15.2(4)GC1' ) flag++;
if ( ver == '15.2(4)GC2' ) flag++;
if ( ver == '15.2(4)GC3' ) flag++;
if ( ver == '15.2(4)M' ) flag++;
if ( ver == '15.2(4)M1' ) flag++;
if ( ver == '15.2(4)M2' ) flag++;
if ( ver == '15.2(4)M3' ) flag++;
if ( ver == '15.2(4)M4' ) flag++;
if ( ver == '15.2(4)M5' ) flag++;
if ( ver == '15.2(4)M6' ) flag++;
if ( ver == '15.2(4)M6a' ) flag++;
if ( ver == '15.2(4)M7' ) flag++;
if ( ver == '15.2(4)M8' ) flag++;
if ( ver == '15.2(4)M9' ) flag++;
if ( ver == '15.2(1)S' ) flag++;
if ( ver == '15.2(1)S1' ) flag++;
if ( ver == '15.2(1)S2' ) flag++;
if ( ver == '15.2(2)S' ) flag++;
if ( ver == '15.2(2)S1' ) flag++;
if ( ver == '15.2(2)S2' ) flag++;
if ( ver == '15.2(4)S' ) flag++;
if ( ver == '15.2(4)S1' ) flag++;
if ( ver == '15.2(4)S2' ) flag++;
if ( ver == '15.2(4)S3' ) flag++;
if ( ver == '15.2(4)S3a' ) flag++;
if ( ver == '15.2(4)S4' ) flag++;
if ( ver == '15.2(4)S4a' ) flag++;
if ( ver == '15.2(4)S5' ) flag++;
if ( ver == '15.2(4)S6' ) flag++;
if ( ver == '15.2(4)S7' ) flag++;
if ( ver == '15.2(2)SNG' ) flag++;
if ( ver == '15.2(2)SNH1' ) flag++;
if ( ver == '15.2(2)SNI' ) flag++;
if ( ver == '15.2(1)SY' ) flag++;
if ( ver == '15.2(1)SY0a' ) flag++;
if ( ver == '15.2(1)SY1' ) flag++;
if ( ver == '15.2(1)SY1a' ) flag++;
if ( ver == '15.2(2)SY' ) flag++;
if ( ver == '15.2(1)T' ) flag++;
if ( ver == '15.2(1)T1' ) flag++;
if ( ver == '15.2(1)T2' ) flag++;
if ( ver == '15.2(1)T3' ) flag++;
if ( ver == '15.2(1)T3a' ) flag++;
if ( ver == '15.2(1)T4' ) flag++;
if ( ver == '15.2(2)T' ) flag++;
if ( ver == '15.2(2)T1' ) flag++;
if ( ver == '15.2(2)T2' ) flag++;
if ( ver == '15.2(2)T3' ) flag++;
if ( ver == '15.2(2)T4' ) flag++;
if ( ver == '15.2(3)T' ) flag++;
if ( ver == '15.2(3)T1' ) flag++;
if ( ver == '15.2(3)T2' ) flag++;
if ( ver == '15.2(3)T3' ) flag++;
if ( ver == '15.2(3)T4' ) flag++;
if ( ver == '15.3(3)M' ) flag++;
if ( ver == '15.3(3)M1' ) flag++;
if ( ver == '15.3(3)M2' ) flag++;
if ( ver == '15.3(3)M3' ) flag++;
if ( ver == '15.3(3)M4' ) flag++;
if ( ver == '15.3(3)M5' ) flag++;
if ( ver == '15.3(3)M6' ) flag++;
if ( ver == '15.3(1)S' ) flag++;
if ( ver == '15.3(1)S1' ) flag++;
if ( ver == '15.3(1)S2' ) flag++;
if ( ver == '15.3(2)S' ) flag++;
if ( ver == '15.3(2)S0a' ) flag++;
if ( ver == '15.3(2)S1' ) flag++;
if ( ver == '15.3(2)S2' ) flag++;
if ( ver == '15.3(3)S' ) flag++;
if ( ver == '15.3(3)S1' ) flag++;
if ( ver == '15.3(3)S2' ) flag++;
if ( ver == '15.3(3)S3' ) flag++;
if ( ver == '15.3(3)S4' ) flag++;
if ( ver == '15.3(3)S5' ) flag++;
if ( ver == '15.3(3)S6' ) flag++;
if ( ver == '15.3(1)T' ) flag++;
if ( ver == '15.3(1)T1' ) flag++;
if ( ver == '15.3(1)T2' ) flag++;
if ( ver == '15.3(1)T3' ) flag++;
if ( ver == '15.3(1)T4' ) flag++;
if ( ver == '15.3(2)T' ) flag++;
if ( ver == '15.3(2)T1' ) flag++;
if ( ver == '15.3(2)T2' ) flag++;
if ( ver == '15.3(2)T3' ) flag++;
if ( ver == '15.3(2)T4' ) flag++;
if ( ver == '15.4(1)CG' ) flag++;
if ( ver == '15.4(1)CG1' ) flag++;
if ( ver == '15.4(2)CG' ) flag++;
if ( ver == '15.4(3)M' ) flag++;
if ( ver == '15.4(3)M1' ) flag++;
if ( ver == '15.4(3)M2' ) flag++;
if ( ver == '15.4(3)M3' ) flag++;
if ( ver == '15.4(3)M4' ) flag++;
if ( ver == '15.4(1)S' ) flag++;
if ( ver == '15.4(1)S1' ) flag++;
if ( ver == '15.4(1)S2' ) flag++;
if ( ver == '15.4(1)S3' ) flag++;
if ( ver == '15.4(1)S4' ) flag++;
if ( ver == '15.4(2)S' ) flag++;
if ( ver == '15.4(2)S1' ) flag++;
if ( ver == '15.4(2)S2' ) flag++;
if ( ver == '15.4(2)S3' ) flag++;
if ( ver == '15.4(2)S4' ) flag++;
if ( ver == '15.4(3)S' ) flag++;
if ( ver == '15.4(3)S1' ) flag++;
if ( ver == '15.4(3)S2' ) flag++;
if ( ver == '15.4(3)S3' ) flag++;
if ( ver == '15.4(3)S4' ) flag++;
if ( ver == '15.4(1)T' ) flag++;
if ( ver == '15.4(1)T1' ) flag++;
if ( ver == '15.4(1)T2' ) flag++;
if ( ver == '15.4(1)T3' ) flag++;
if ( ver == '15.4(1)T4' ) flag++;
if ( ver == '15.4(2)T' ) flag++;
if ( ver == '15.4(2)T1' ) flag++;
if ( ver == '15.4(2)T2' ) flag++;
if ( ver == '15.4(2)T3' ) flag++;
if ( ver == '15.4(2)T4' ) flag++;
if ( ver == '15.5(3)M' ) flag++;
if ( ver == '15.5(3)M0a' ) flag++;
if ( ver == '15.5(3)M1' ) flag++;
if ( ver == '15.5(1)S' ) flag++;
if ( ver == '15.5(1)S1' ) flag++;
if ( ver == '15.5(1)S2' ) flag++;
if ( ver == '15.5(1)S3' ) flag++;
if ( ver == '15.5(2)S' ) flag++;
if ( ver == '15.5(2)S1' ) flag++;
if ( ver == '15.5(2)S2' ) flag++;
if ( ver == '15.5(3)S' ) flag++;
if ( ver == '15.5(3)S0a' ) flag++;
if ( ver == '15.5(3)S1' ) flag++;
if ( ver == '15.5(3)S1a' ) flag++;
if ( ver == '15.5(3)SN' ) flag++;
if ( ver == '15.5(1)T' ) flag++;
if ( ver == '15.5(1)T1' ) flag++;
if ( ver == '15.5(1)T2' ) flag++;
if ( ver == '15.5(1)T3' ) flag++;
if ( ver == '15.5(2)T' ) flag++;
if ( ver == '15.5(2)T1' ) flag++;
if ( ver == '15.5(2)T2' ) flag++;
if ( ver == '15.6(1)T0a' ) flag++;

# Check that IKEv2 fragmentation or IKEv2 is running
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;

  # Check for condition 1, IKEv2 fragmentation
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config","show running-config");
  if (check_cisco_result(buf))
  {
    if ("crypto ikev2 fragmentation" >< buf) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }

  # Check for condition 2, IKEv2 is running
  if (flag)
  {
    flag = 0;

    pat = "(\d+.\d+.\d+.\d+|.*:.*|UNKNOWN|--any--)\s+(500|848|4500)\s";
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_sockets","show ip sockets");
    if (!flag)
    {
      if (check_cisco_result(buf))
      {
        if (
          preg(multiline:TRUE, pattern:pat, string:buf)
        ) flag = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        flag = 1;
        override = 1;
      }
    }

    if (!flag)
    {
      buf = cisco_command_kb_item("Host/Cisco/Config/show_udp","show udp");
      if (check_cisco_result(buf))
      {
        if (
          preg(multiline:TRUE, pattern:pat, string:buf)
        ) flag = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        flag = 1;
        override = 1;
      }
    }
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCux38417' +
      '\n  Installed release : ' + ver +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
