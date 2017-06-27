#TRUSTED 4b1d7c41d5c67ee704de6f4c8fd6658f3c8727f9ad195dd7df3abd01db6e0aac41acc8915e7a2910693be4c60f59878944203bb3c228564e0dc80b4c6401911f52ae13809f2f16aa88b99ad93b6f9e2e1873831681d0ce4596d164a82d55acd4cfdba55618c3ab465487750b400d3eb5ec33c5e239cf061d952ee77f539fe4a31e8b1fad24b1381374d41a4bd03507279f47f8c2d88fee2b14347856bcbb47a7493c5d493681927761e6cce8a805d689936f62d20a70f404fd06e268fb15ef4fe7eeeca87f7639ff45d5b2c7c7c3a63d7ff55e28c84c9417d90a46e50379a1d96f033dc22447933951caae9f3de9e1ba108b90d7adb5d7ddadd139cb9ebffd3ab60bc16a29f4ff7a0c14e5777642450093d035aa0d6fd8cedfb955cc309627208faea929367ba13459f8f78bb4091b7ffdd8c641020386017f992ac262df494120ffd9be1f63451c661232f91a0f533d4f890069c3b86ff0651ebc54b1b6a4b23183f8ab0d167b203bc28762dfdd6d9b34380485f3b05b11afea0042ef4aa9d05df274bfd9f1da101bd82ef5d577d9a2dc290be0244a28679bde89a9c95bb407efdaac6896870239d491b49660d62ab929ac3f985a512f68a4c5b681ac78a0ff4ae81516ccc5d6ee724b1a43cb31e6f841ce5c0cd471a58b0064f46c82c749c35fc8111c14948a7550a17e76797e3917ca4b5444625b8aefac5b331257eda313
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99026);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/31");

  script_cve_id("CVE-2017-3864");
  script_bugtraq_id(97012);
  script_osvdb_id(154190);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu43892");
  script_xref(name:"IAVA", value:"2017-A-0082");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170322-dhcpc");

  script_name(english:"Cisco IOS DHCP Client DoS (cisco-sa-20170322-dhcpc)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by a denial of service vulnerability
in the DHCP client implementation when parsing DHCP packets. An
unauthenticated, remote attacker can exploit this issue, via specially
crafted DHCP packets, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170322-dhcpc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d54a2ce");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuu43892");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuu43892.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

# Check for vuln versions
if (
  ver == '12.2(33)MRA' ||
  ver == '12.2(33)MRB' ||
  ver == '12.2(33)MRB1' ||
  ver == '12.2(33)MRB2' ||
  ver == '12.2(33)MRB3' ||
  ver == '12.2(33)MRB4' ||
  ver == '12.2(33)MRB5' ||
  ver == '12.2(33)MRB6' ||
  ver == '12.2(33)SRD' ||
  ver == '12.2(33)SRD1' ||
  ver == '12.2(33)SRD2' ||
  ver == '12.2(33)SRD2a' ||
  ver == '12.2(33)SRD3' ||
  ver == '12.2(33)SRD4' ||
  ver == '12.2(33)SRD5' ||
  ver == '12.2(33)SRD6' ||
  ver == '12.2(33)SRD7' ||
  ver == '12.2(33)SRD8' ||
  ver == '12.2(33)SRE' ||
  ver == '12.2(33)SRE0a' ||
  ver == '12.2(33)SRE1' ||
  ver == '12.2(33)SRE2' ||
  ver == '12.2(33)SXH5' ||
  ver == '12.2(33)SXH6' ||
  ver == '12.2(33)SXH7' ||
  ver == '12.2(33)SXH8' ||
  ver == '12.2(33)SXH8a' ||
  ver == '12.2(33)SXH8b' ||
  ver == '12.2(33)SXI' ||
  ver == '12.2(33)SXI1' ||
  ver == '12.2(33)SXI10' ||
  ver == '12.2(33)SXI11' ||
  ver == '12.2(33)SXI12' ||
  ver == '12.2(33)SXI13' ||
  ver == '12.2(33)SXI14' ||
  ver == '12.2(33)SXI2' ||
  ver == '12.2(33)SXI2a' ||
  ver == '12.2(33)SXI3' ||
  ver == '12.2(33)SXI4' ||
  ver == '12.2(33)SXI4a' ||
  ver == '12.2(33)SXI5' ||
  ver == '12.2(33)SXI6' ||
  ver == '12.2(33)SXI7' ||
  ver == '12.2(33)SXI8' ||
  ver == '12.2(33)SXI8a' ||
  ver == '12.2(33)SXI9' ||
  ver == '12.2(33)SXJ' ||
  ver == '12.2(33)SXJ1' ||
  ver == '12.2(33)SXJ10' ||
  ver == '12.2(33)SXJ2' ||
  ver == '12.2(33)SXJ3' ||
  ver == '12.2(33)SXJ4' ||
  ver == '12.2(33)SXJ5' ||
  ver == '12.2(33)SXJ6' ||
  ver == '12.2(33)SXJ7' ||
  ver == '12.2(33)SXJ8' ||
  ver == '12.2(33)SXJ9' ||
  ver == '12.2(50)SY' ||
  ver == '12.2(50)SY1' ||
  ver == '12.2(50)SY2' ||
  ver == '12.2(50)SY3' ||
  ver == '12.2(50)SY4' ||
  ver == '12.4(15)T10' ||
  ver == '12.4(15)T11' ||
  ver == '12.4(15)T12' ||
  ver == '12.4(15)T13' ||
  ver == '12.4(15)T14' ||
  ver == '12.4(15)T15' ||
  ver == '12.4(15)T16' ||
  ver == '12.4(15)T17' ||
  ver == '12.4(15)T9' ||
  ver == '12.4(15)XZ' ||
  ver == '12.4(15)XZ1' ||
  ver == '12.4(15)XZ2' ||
  ver == '12.4(19)MR' ||
  ver == '12.4(19)MR1' ||
  ver == '12.4(19)MR2' ||
  ver == '12.4(19)MR3' ||
  ver == '12.4(20)MR' ||
  ver == '12.4(20)MR2' ||
  ver == '12.4(20)MRB' ||
  ver == '12.4(20)MRB1' ||
  ver == '12.4(20)T' ||
  ver == '12.4(20)T1' ||
  ver == '12.4(20)T2' ||
  ver == '12.4(20)T3' ||
  ver == '12.4(20)T4' ||
  ver == '12.4(20)T5' ||
  ver == '12.4(20)T6' ||
  ver == '12.4(20)YA' ||
  ver == '12.4(20)YA1' ||
  ver == '12.4(20)YA2' ||
  ver == '12.4(20)YA3' ||
  ver == '12.4(21)' ||
  ver == '12.4(21a)' ||
  ver == '12.4(21a)JA' ||
  ver == '12.4(21a)JA1' ||
  ver == '12.4(21a)JA2' ||
  ver == '12.4(21a)JHA' ||
  ver == '12.4(21a)JHC' ||
  ver == '12.4(21a)JX' ||
  ver == '12.4(21a)JY' ||
  ver == '12.4(22)GC1' ||
  ver == '12.4(22)MD' ||
  ver == '12.4(22)MD1' ||
  ver == '12.4(22)MD2' ||
  ver == '12.4(22)MDA' ||
  ver == '12.4(22)MDA1' ||
  ver == '12.4(22)MDA2' ||
  ver == '12.4(22)MDA3' ||
  ver == '12.4(22)MDA4' ||
  ver == '12.4(22)MDA5' ||
  ver == '12.4(22)MDA6' ||
  ver == '12.4(22)T' ||
  ver == '12.4(22)T1' ||
  ver == '12.4(22)T2' ||
  ver == '12.4(22)T3' ||
  ver == '12.4(22)T4' ||
  ver == '12.4(22)T5' ||
  ver == '12.4(22)XR1' ||
  ver == '12.4(22)XR10' ||
  ver == '12.4(22)XR11' ||
  ver == '12.4(22)XR12' ||
  ver == '12.4(22)XR2' ||
  ver == '12.4(22)XR3' ||
  ver == '12.4(22)XR4' ||
  ver == '12.4(22)XR5' ||
  ver == '12.4(22)XR6' ||
  ver == '12.4(22)XR7' ||
  ver == '12.4(22)XR8' ||
  ver == '12.4(22)XR9' ||
  ver == '12.4(22)YB' ||
  ver == '12.4(22)YB1' ||
  ver == '12.4(22)YB2' ||
  ver == '12.4(22)YB3' ||
  ver == '12.4(22)YB4' ||
  ver == '12.4(22)YB5' ||
  ver == '12.4(22)YB6' ||
  ver == '12.4(22)YB7' ||
  ver == '12.4(22)YB8' ||
  ver == '12.4(22)YD' ||
  ver == '12.4(22)YD1' ||
  ver == '12.4(22)YD2' ||
  ver == '12.4(22)YD3' ||
  ver == '12.4(22)YD4' ||
  ver == '12.4(22)YE' ||
  ver == '12.4(22)YE1' ||
  ver == '12.4(22)YE2' ||
  ver == '12.4(22)YE3' ||
  ver == '12.4(22)YE4' ||
  ver == '12.4(22)YE5' ||
  ver == '12.4(22)YE6' ||
  ver == '12.4(23)' ||
  ver == '12.4(23a)' ||
  ver == '12.4(23b)' ||
  ver == '12.4(23c)JA' ||
  ver == '12.4(23c)JA1' ||
  ver == '12.4(23c)JA10' ||
  ver == '12.4(23c)JA2' ||
  ver == '12.4(23c)JA3' ||
  ver == '12.4(23c)JA4' ||
  ver == '12.4(23c)JA5' ||
  ver == '12.4(23c)JA6' ||
  ver == '12.4(23c)JA7' ||
  ver == '12.4(23c)JA8' ||
  ver == '12.4(23c)JA9' ||
  ver == '12.4(23c)JY' ||
  ver == '12.4(23c)JZ' ||
  ver == '12.4(24)GC1' ||
  ver == '12.4(24)GC3' ||
  ver == '12.4(24)GC3a' ||
  ver == '12.4(24)GC4' ||
  ver == '12.4(24)GC5' ||
  ver == '12.4(24)MD' ||
  ver == '12.4(24)MD1' ||
  ver == '12.4(24)MD2' ||
  ver == '12.4(24)MD3' ||
  ver == '12.4(24)MD4' ||
  ver == '12.4(24)MD5' ||
  ver == '12.4(24)MD6' ||
  ver == '12.4(24)MD7' ||
  ver == '12.4(24)MDA1' ||
  ver == '12.4(24)MDA10' ||
  ver == '12.4(24)MDA11' ||
  ver == '12.4(24)MDA12' ||
  ver == '12.4(24)MDA13' ||
  ver == '12.4(24)MDA2' ||
  ver == '12.4(24)MDA3' ||
  ver == '12.4(24)MDA4' ||
  ver == '12.4(24)MDA5' ||
  ver == '12.4(24)MDA6' ||
  ver == '12.4(24)MDA7' ||
  ver == '12.4(24)MDA8' ||
  ver == '12.4(24)MDA9' ||
  ver == '12.4(24)MDB' ||
  ver == '12.4(24)MDB1' ||
  ver == '12.4(24)MDB10' ||
  ver == '12.4(24)MDB11' ||
  ver == '12.4(24)MDB12' ||
  ver == '12.4(24)MDB13' ||
  ver == '12.4(24)MDB14' ||
  ver == '12.4(24)MDB15' ||
  ver == '12.4(24)MDB16' ||
  ver == '12.4(24)MDB17' ||
  ver == '12.4(24)MDB18' ||
  ver == '12.4(24)MDB19' ||
  ver == '12.4(24)MDB3' ||
  ver == '12.4(24)MDB4' ||
  ver == '12.4(24)MDB5' ||
  ver == '12.4(24)MDB5a' ||
  ver == '12.4(24)MDB6' ||
  ver == '12.4(24)MDB7' ||
  ver == '12.4(24)MDB8' ||
  ver == '12.4(24)MDB9' ||
  ver == '12.4(24)T' ||
  ver == '12.4(24)T1' ||
  ver == '12.4(24)T2' ||
  ver == '12.4(24)T3' ||
  ver == '12.4(24)T3e' ||
  ver == '12.4(24)T3f' ||
  ver == '12.4(24)T4' ||
  ver == '12.4(24)T4a' ||
  ver == '12.4(24)T4b' ||
  ver == '12.4(24)T4c' ||
  ver == '12.4(24)T4d' ||
  ver == '12.4(24)T4e' ||
  ver == '12.4(24)T4f' ||
  ver == '12.4(24)T4l' ||
  ver == '12.4(24)T5' ||
  ver == '12.4(24)T6' ||
  ver == '12.4(24)T7' ||
  ver == '12.4(24)T8' ||
  ver == '12.4(24)YE' ||
  ver == '12.4(24)YE1' ||
  ver == '12.4(24)YE2' ||
  ver == '12.4(24)YE3' ||
  ver == '12.4(24)YE3a' ||
  ver == '12.4(24)YE3b' ||
  ver == '12.4(24)YE3c' ||
  ver == '12.4(24)YE3d' ||
  ver == '12.4(24)YE3e' ||
  ver == '12.4(24)YE4' ||
  ver == '12.4(24)YE5' ||
  ver == '12.4(24)YE6' ||
  ver == '12.4(24)YE7' ||
  ver == '12.4(24)YG1' ||
  ver == '12.4(24)YG2' ||
  ver == '12.4(24)YG3' ||
  ver == '12.4(24)YG4' ||
  ver == '12.4(25)' ||
  ver == '12.4(25a)' ||
  ver == '12.4(25b)' ||
  ver == '12.4(25c)' ||
  ver == '12.4(25d)' ||
  ver == '12.4(25d)JA' ||
  ver == '12.4(25d)JA1' ||
  ver == '12.4(25d)JA2' ||
  ver == '12.4(25d)JAX' ||
  ver == '12.4(25d)JAX1' ||
  ver == '12.4(25e)' ||
  ver == '12.4(25e)JA' ||
  ver == '12.4(25e)JA1' ||
  ver == '12.4(25e)JAL' ||
  ver == '12.4(25e)JAL1' ||
  ver == '12.4(25e)JAL1a' ||
  ver == '12.4(25e)JAL2' ||
  ver == '12.4(25e)JAM' ||
  ver == '12.4(25e)JAM2' ||
  ver == '12.4(25e)JAM3' ||
  ver == '12.4(25e)JAM4' ||
  ver == '12.4(25e)JAM5' ||
  ver == '12.4(25e)JAM6' ||
  ver == '12.4(25e)JAN1' ||
  ver == '12.4(25e)JAO' ||
  ver == '12.4(25e)JAO1' ||
  ver == '12.4(25e)JAO2' ||
  ver == '12.4(25e)JAO3' ||
  ver == '12.4(25e)JAO4' ||
  ver == '12.4(25e)JAO5' ||
  ver == '12.4(25e)JAO6' ||
  ver == '12.4(25e)JAP' ||
  ver == '12.4(25e)JAP1' ||
  ver == '12.4(25e)JAP10' ||
  ver == '12.4(25e)JAP100' ||
  ver == '12.4(25e)JAP26' ||
  ver == '12.4(25e)JAP4' ||
  ver == '12.4(25e)JAP5' ||
  ver == '12.4(25e)JAP6' ||
  ver == '12.4(25e)JAP7' ||
  ver == '12.4(25e)JAP8' ||
  ver == '12.4(25e)JAP9' ||
  ver == '12.4(25e)JAX' ||
  ver == '12.4(25e)JAX1' ||
  ver == '12.4(25e)JAX2' ||
  ver == '12.4(25e)JAZ' ||
  ver == '12.4(25e)JX' ||
  ver == '12.4(25f)' ||
  ver == '12.4(25g)' ||
  ver == '15.0(1)M' ||
  ver == '15.0(1)M1' ||
  ver == '15.0(1)M10' ||
  ver == '15.0(1)M2' ||
  ver == '15.0(1)M3' ||
  ver == '15.0(1)M4' ||
  ver == '15.0(1)M5' ||
  ver == '15.0(1)M6' ||
  ver == '15.0(1)M7' ||
  ver == '15.0(1)M8' ||
  ver == '15.0(1)M9' ||
  ver == '15.0(1)SY' ||
  ver == '15.0(1)SY1' ||
  ver == '15.0(1)SY10' ||
  ver == '15.0(1)SY2' ||
  ver == '15.0(1)SY3' ||
  ver == '15.0(1)SY4' ||
  ver == '15.0(1)SY5' ||
  ver == '15.0(1)SY6' ||
  ver == '15.0(1)SY7' ||
  ver == '15.0(1)SY7a' ||
  ver == '15.0(1)SY8' ||
  ver == '15.0(1)SY9' ||
  ver == '15.0(1)XA' ||
  ver == '15.0(1)XA1' ||
  ver == '15.0(1)XA2' ||
  ver == '15.0(1)XA3' ||
  ver == '15.0(1)XA4' ||
  ver == '15.0(1)XA5' ||
  ver == '15.0(2)EJ' ||
  ver == '15.0(2)EJ1' ||
  ver == '15.0(2)SE10' ||
  ver == '15.0(2)SE3' ||
  ver == '15.0(2)SE4' ||
  ver == '15.0(2)SE5' ||
  ver == '15.0(2)SE6' ||
  ver == '15.0(2)SE7' ||
  ver == '15.0(2)SE8' ||
  ver == '15.0(2)SE9' ||
  ver == '15.0(2a)SE9' ||
  ver == '15.1(1)SY' ||
  ver == '15.1(1)SY1' ||
  ver == '15.1(1)SY2' ||
  ver == '15.1(1)SY3' ||
  ver == '15.1(1)SY4' ||
  ver == '15.1(1)SY5' ||
  ver == '15.1(1)SY6' ||
  ver == '15.1(1)T' ||
  ver == '15.1(1)T1' ||
  ver == '15.1(1)T2' ||
  ver == '15.1(1)T3' ||
  ver == '15.1(1)T4' ||
  ver == '15.1(1)T5' ||
  ver == '15.1(1)XB' ||
  ver == '15.1(2)GC' ||
  ver == '15.1(2)GC1' ||
  ver == '15.1(2)GC2' ||
  ver == '15.1(2)SY' ||
  ver == '15.1(2)SY1' ||
  ver == '15.1(2)SY2' ||
  ver == '15.1(2)SY3' ||
  ver == '15.1(2)SY4' ||
  ver == '15.1(2)SY4a' ||
  ver == '15.1(2)SY5' ||
  ver == '15.1(2)SY6' ||
  ver == '15.1(2)SY7' ||
  ver == '15.1(2)T' ||
  ver == '15.1(2)T0a' ||
  ver == '15.1(2)T1' ||
  ver == '15.1(2)T2' ||
  ver == '15.1(2)T2a' ||
  ver == '15.1(2)T3' ||
  ver == '15.1(2)T4' ||
  ver == '15.1(2)T5' ||
  ver == '15.1(3)T' ||
  ver == '15.1(3)T1' ||
  ver == '15.1(3)T2' ||
  ver == '15.1(3)T3' ||
  ver == '15.1(3)T4' ||
  ver == '15.1(4)GC' ||
  ver == '15.1(4)GC1' ||
  ver == '15.1(4)GC2' ||
  ver == '15.1(4)M' ||
  ver == '15.1(4)M1' ||
  ver == '15.1(4)M10' ||
  ver == '15.1(4)M2' ||
  ver == '15.1(4)M3' ||
  ver == '15.1(4)M3a' ||
  ver == '15.1(4)M4' ||
  ver == '15.1(4)M5' ||
  ver == '15.1(4)M6' ||
  ver == '15.1(4)M7' ||
  ver == '15.1(4)M8' ||
  ver == '15.1(4)M9' ||
  ver == '15.2(1)E' ||
  ver == '15.2(1)E1' ||
  ver == '15.2(1)E2' ||
  ver == '15.2(1)E3' ||
  ver == '15.2(1)EY' ||
  ver == '15.2(1)GC' ||
  ver == '15.2(1)GC1' ||
  ver == '15.2(1)GC2' ||
  ver == '15.2(1)SY' ||
  ver == '15.2(1)SY0a' ||
  ver == '15.2(1)SY1' ||
  ver == '15.2(1)SY1a' ||
  ver == '15.2(1)SY2' ||
  ver == '15.2(1)T' ||
  ver == '15.2(1)T1' ||
  ver == '15.2(1)T2' ||
  ver == '15.2(1)T3' ||
  ver == '15.2(1)T3a' ||
  ver == '15.2(1)T4' ||
  ver == '15.2(2)E' ||
  ver == '15.2(2)E1' ||
  ver == '15.2(2)E2' ||
  ver == '15.2(2)E4' ||
  ver == '15.2(2)EB' ||
  ver == '15.2(2)EB1' ||
  ver == '15.2(2)EB2' ||
  ver == '15.2(2)GC' ||
  ver == '15.2(2)JA' ||
  ver == '15.2(2)JA1' ||
  ver == '15.2(2)JAX' ||
  ver == '15.2(2)JAX1' ||
  ver == '15.2(2)JB' ||
  ver == '15.2(2)JB2' ||
  ver == '15.2(2)JB3' ||
  ver == '15.2(2)JB4' ||
  ver == '15.2(2)JB5' ||
  ver == '15.2(2)JB6' ||
  ver == '15.2(2)SY' ||
  ver == '15.2(2)SY1' ||
  ver == '15.2(2)T' ||
  ver == '15.2(2)T1' ||
  ver == '15.2(2)T2' ||
  ver == '15.2(2)T3' ||
  ver == '15.2(2)T4' ||
  ver == '15.2(2a)E1' ||
  ver == '15.2(3)E' ||
  ver == '15.2(3)E1' ||
  ver == '15.2(3)E2' ||
  ver == '15.2(3)E3' ||
  ver == '15.2(3)GC' ||
  ver == '15.2(3)GC1' ||
  ver == '15.2(3)T' ||
  ver == '15.2(3)T1' ||
  ver == '15.2(3)T2' ||
  ver == '15.2(3)T3' ||
  ver == '15.2(3)T4' ||
  ver == '15.2(3a)E' ||
  ver == '15.2(3m)E2' ||
  ver == '15.2(4)GC' ||
  ver == '15.2(4)GC1' ||
  ver == '15.2(4)GC2' ||
  ver == '15.2(4)GC3' ||
  ver == '15.2(4)JA' ||
  ver == '15.2(4)JA1' ||
  ver == '15.2(4)JB' ||
  ver == '15.2(4)JB1' ||
  ver == '15.2(4)JB2' ||
  ver == '15.2(4)JB3' ||
  ver == '15.2(4)JB3a' ||
  ver == '15.2(4)JB3b' ||
  ver == '15.2(4)JB3h' ||
  ver == '15.2(4)JB3s' ||
  ver == '15.2(4)JB4' ||
  ver == '15.2(4)JB5' ||
  ver == '15.2(4)JB5h' ||
  ver == '15.2(4)JB5m' ||
  ver == '15.2(4)JB6' ||
  ver == '15.2(4)JN' ||
  ver == '15.2(4)M' ||
  ver == '15.2(4)M1' ||
  ver == '15.2(4)M10' ||
  ver == '15.2(4)M11' ||
  ver == '15.2(4)M2' ||
  ver == '15.2(4)M3' ||
  ver == '15.2(4)M4' ||
  ver == '15.2(4)M5' ||
  ver == '15.2(4)M6' ||
  ver == '15.2(4)M6a' ||
  ver == '15.2(4)M7' ||
  ver == '15.2(4)M8' ||
  ver == '15.2(4)M9' ||
  ver == '15.3(1)SY' ||
  ver == '15.3(1)T' ||
  ver == '15.3(1)T1' ||
  ver == '15.3(1)T2' ||
  ver == '15.3(1)T3' ||
  ver == '15.3(1)T4' ||
  ver == '15.3(2)T' ||
  ver == '15.3(2)T1' ||
  ver == '15.3(2)T2' ||
  ver == '15.3(2)T3' ||
  ver == '15.3(2)T4' ||
  ver == '15.3(3)JA' ||
  ver == '15.3(3)JA1' ||
  ver == '15.3(3)JA10' ||
  ver == '15.3(3)JA1m' ||
  ver == '15.3(3)JA1n' ||
  ver == '15.3(3)JA4' ||
  ver == '15.3(3)JA5' ||
  ver == '15.3(3)JA6' ||
  ver == '15.3(3)JA7' ||
  ver == '15.3(3)JA76' ||
  ver == '15.3(3)JA77' ||
  ver == '15.3(3)JA78' ||
  ver == '15.3(3)JA8' ||
  ver == '15.3(3)JA9' ||
  ver == '15.3(3)JAA' ||
  ver == '15.3(3)JAB' ||
  ver == '15.3(3)JAX' ||
  ver == '15.3(3)JAX1' ||
  ver == '15.3(3)JAX2' ||
  ver == '15.3(3)JB' ||
  ver == '15.3(3)JB75' ||
  ver == '15.3(3)JBB' ||
  ver == '15.3(3)JBB1' ||
  ver == '15.3(3)JBB2' ||
  ver == '15.3(3)JBB4' ||
  ver == '15.3(3)JBB5' ||
  ver == '15.3(3)JBB6' ||
  ver == '15.3(3)JBB8' ||
  ver == '15.3(3)JC' ||
  ver == '15.3(3)JC1' ||
  ver == '15.3(3)JC2' ||
  ver == '15.3(3)JC3' ||
  ver == '15.3(3)JC4' ||
  ver == '15.3(3)JD' ||
  ver == '15.3(3)JN3' ||
  ver == '15.3(3)JN4' ||
  ver == '15.3(3)JN7' ||
  ver == '15.3(3)JN8' ||
  ver == '15.3(3)JN9' ||
  ver == '15.3(3)JNB' ||
  ver == '15.3(3)JNB1' ||
  ver == '15.3(3)JNB2' ||
  ver == '15.3(3)JNB3' ||
  ver == '15.3(3)JNB4' ||
  ver == '15.3(3)JNC' ||
  ver == '15.3(3)JNC1' ||
  ver == '15.3(3)JNC2' ||
  ver == '15.3(3)JNC3' ||
  ver == '15.3(3)JND' ||
  ver == '15.3(3)JNP' ||
  ver == '15.3(3)JNP1' ||
  ver == '15.3(3)JNP2' ||
  ver == '15.3(3)JNP3' ||
  ver == '15.3(3)JPB' ||
  ver == '15.3(3)JPB1' ||
  ver == '15.3(3)JPB2' ||
  ver == '15.3(3)JPC' ||
  ver == '15.3(3)JPC1' ||
  ver == '15.3(3)JPC2' ||
  ver == '15.3(3)M' ||
  ver == '15.3(3)M1' ||
  ver == '15.3(3)M2' ||
  ver == '15.3(3)M3' ||
  ver == '15.3(3)M4' ||
  ver == '15.3(3)M5' ||
  ver == '15.3(3)M6' ||
  ver == '15.3(3)M7' ||
  ver == '15.3(3)M8' ||
  ver == '15.4(1)CG' ||
  ver == '15.4(1)CG1' ||
  ver == '15.4(1)T' ||
  ver == '15.4(1)T1' ||
  ver == '15.4(1)T2' ||
  ver == '15.4(1)T3' ||
  ver == '15.4(1)T4' ||
  ver == '15.4(2)CG' ||
  ver == '15.4(2)T' ||
  ver == '15.4(2)T1' ||
  ver == '15.4(2)T2' ||
  ver == '15.4(2)T3' ||
  ver == '15.4(2)T4' ||
  ver == '15.4(3)M' ||
  ver == '15.4(3)M1' ||
  ver == '15.4(3)M2' ||
  ver == '15.4(3)M3' ||
  ver == '15.4(3)M4' ||
  ver == '15.4(3)M5' ||
  ver == '15.4(3)M6' ||
  ver == '15.4(3)M6a' ||
  ver == '15.5(1)T' ||
  ver == '15.5(1)T1' ||
  ver == '15.5(1)T2' ||
  ver == '15.5(1)T3' ||
  ver == '15.5(1)T4' ||
  ver == '15.5(2)T' ||
  ver == '15.5(2)T1' ||
  ver == '15.5(2)T2' ||
  ver == '15.5(2)T3' ||
  ver == '15.5(2)T4' ||
  ver == '15.5(3)M' ||
  ver == '15.5(3)M0a' ||
  ver == '15.5(3)M1' ||
  ver == '15.5(3)M2' ||
  ver == '15.6(1)T' ||
  ver == '15.6(1)T0a' ||
  ver == '15.6(1)T1' ||
  ver == '15.6(1)T2' ||
  ver == '15.6(2)T' ||
  ver == '15.6(2)T1' ||
  ver == '15.6(3)M' ||
  ver == '15.6(3)M0a'
) flag++;

cmds = make_list();
# Check that device is configured as a DHCP client
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show running-config | include dhcp", "show running-config | include dhcp");
  if (check_cisco_result(buf))
  {
    if ("dhcp" >< buf)
    {
      cmds = make_list(cmds, "show running-config | include dhcp");
      # Check if device is configured as a DHCP server or DHCP relay agent
      buf2 =  cisco_command_kb_item("Host/Cisco/Config/show running-config | include helper|(ip dhcp pool)", "show running-config | include helper|(ip dhcp pool)");
      if (check_cisco_result(buf2))
      {
        if (preg(multiline:TRUE, pattern:"ip helper-address [0-9\.]+", string:buf2))
        {
          cmds = make_list(cmds,"show running-config | include helper|(ip dhcp pool)");
          # Check if device is configured to send DHCP Inform/Discover messages
          # If device is confiured to send DHCP Inform and Discover messages
          # then not vuln
          buf3 = cisco_command_kb_item("Host/Cisco/Config/show running-config | include (ip dhcp-client network-discovery)", "show running-config | include (ip dhcp-client network-discovery)");
          if (check_cisco_result(buf3))
          {
            if (preg(multiline:TRUE, pattern:"ip dhcp-client network-discovery informs .* discovers .*", string:buf3))
            {
              flag = 0;
            }
            else
            {
              flag = 1;
              cmds = make_list(cmds,"show running-config | include (ip dhcp-client network-discovery)");
            }
          }
        }
      }
    }
  }
  else if (cisco_needs_enable(buf))
    override = 1;

  if (!flag && !override) audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS", ver);
}

if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : "CSCuu43892",
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
