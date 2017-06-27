#TRUSTED 3bc80b0d4c6e68cc96384494ae9a956224b06c07e3993989a199b13473624bd70c0a117b309e718024c4c9bbe3d77c6cdb1afcb87f7cc6591370db899c28476d7389392a2b92e2733b3372036f900e1f26a2315f74c90eb31da32acf625d2d49e96ad4f2eb133aecdf51b9439f1f81960c1b814b8bdde4f0df2c9fe778cdb8255d2c13db2c8f2f199b00b5ee4d3ebb764d4a65e2e3fb51d74b03c61cdf7f60f5ae870000729094d4342b4d3396f6e4618b8c80a0d1e9d09f2530bf78dcee96398f7a822911b365d553f431316e28dafcc52b1d8c017f0cfd862eebffaa47a5e8962ce4194a7a0406db2e3eb9ca4dcf9176a9916613faa7b45b58929c1bb6cd997bbde34cb8f7fe243a0bcf9f354de29829c16a892ed3323714b87e8e315b14de833f8c5610fdbd8f2c369b9f77bc90c3758aba520e51acc085491bc4ab8f10e216c886703b2a361f82fa33fc90d7bb58df884181f6c3ea95e63e68b6cc491d34bfb654c21884d831e825f3d11a88871fa20922c559c39d0bf840552b35d0e810e33ffdebea0defb67e7857904e6e871fcab8ec1d88ce764528ac9d53a7fe2d2434d5862ef11ba7c74725ccc8f8b197269541738c995e360a530c1afc4b0f515a51146b29a5c532ded8ceb2757a6bc812e57b03ca2fcaa275303102135c64f2e3d5e6607043c8ca8c56a9b29baf7bfe30b1d65cb8aa742b53fb51c4892d147c24
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97945);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/31");

  script_cve_id("CVE-2017-3850");
  script_bugtraq_id(96971);
  script_osvdb_id(154053);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc42729");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170320-aniipv6");

  script_name(english:"Cisco IOS ANI IPv6 Packets DoS (cisco-sa-20170320-aniipv6)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by a denial of service vulnerability
in the Autonomic Networking Infrastructure (ANI) component due to
incomplete input validation of certain crafted IPv6 packets. An
unauthenticated, remote attacker can exploit this issue, via specially
crafted IPv6 packets, to cause the device to reload.

Note that this issue only affect devices with ANI enabled that have a
reachable IPv6 interface.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170320-aniipv6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d249229");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20170320-aniipv6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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

affected_versions = [
  '15.3(3)S',
  '15.3(3)S1',
  '15.3(3)S2',
  '15.3(3)S3',
  '15.3(3)S6',
  '15.3(3)S4',
  '15.3(3)S5',
  '15.2(3)E',
  '15.2(4)E',
  '15.2(3)E1',
  '15.2(3)E2',
  '15.2(3)E3',
  '15.2(4)E1',
  '15.2(4)E2',
  '15.2(5)E',
  '15.2(5b)E',
  '15.4(1)S',
  '15.4(3)S',
  '15.4(1)S1',
  '15.4(1)S2',
  '15.4(2)S1',
  '15.4(1)S3',
  '15.4(3)S1',
  '15.4(2)S2',
  '15.4(3)S2',
  '15.4(3)S3',
  '15.4(1)S4',
  '15.4(2)S3',
  '15.4(2)S4',
  '15.4(3)S4',
  '15.4(3)S5',
  '15.4(3)S6',
  '15.5(1)S',
  '15.5(2)S',
  '15.5(1)S1',
  '15.5(3)S',
  '15.5(1)S2',
  '15.5(1)S3',
  '15.5(2)S1',
  '15.5(2)S2',
  '15.5(3)S1',
  '15.5(3)S1a',
  '15.5(2)S3',
  '15.5(3)S2',
  '15.5(3)S0a',
  '15.5(3)S3',
  '15.5(1)S4',
  '15.5(3)SN',
  '15.6(1)S',
  '15.6(2)S',
  '15.6(2)S1',
  '15.6(1)S1',
  '15.6(1)S2',
  '15.6(1)T',
  '15.6(2)T',
  '15.6(1)T0a',
  '15.6(1)T1',
  '15.6(2)T1',
  '15.6(1)T2',
  '15.6(2)T2',
  '15.6(2)SN',
  '15.6(3)M'
];

foreach affected_version (affected_versions)
  if (ver == affected_version)
    flag++;

# Check that ANI is running and an IPv6 interface is enabled
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_run_autonomic","show run | include autonomic");
  if (check_cisco_result(buf))
  {
    if ( !empty_or_null(buf) && "no autonomic" >!< buf )
    {
      buf2 = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_interface", "show ipv6 interface");
      if (check_cisco_result(buf2))
      {
        if (preg(multiline: TRUE, pattern:"IPv6\s+is\s+enabled", string:buf2))
          flag = 1;
      }
    }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag) security_report_cisco(severity:SECURITY_HOLE, port:0, version:ver, bug_id:'CSCvc42717', override:override);
else audit(AUDIT_HOST_NOT, "affected");
