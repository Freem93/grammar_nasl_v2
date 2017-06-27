#TRUSTED 3bd6a071643fef2e3b7597294f3dd1c70771a512b79a793c92143ee4d54bac27930cf6468246577b4c5c920b98a94047743c6096ca628ddadf95fce3528ee4d243954aab44c1aebccbcaba6a137ba540183a83a6faf99e2e12955f8d978a946b360fcb75479c0b299ee3eecee7715536f5b66de755a2742481e74e2f677365849e742a367c5676c077ae6d4ef5cbf87def4ca439a30c88ae3281393c8ef151c79ac72b362fab01a61af195fcb9ee18592730f26eeeaf6e10f9787df8a9337a4c0bd77934fd47858f8c1441333f73d2ed6a9fc8312c66265ee5b70a25df5013e3e1a26bf1d6aa899686851fced3f9f3ed127be62756945a930371dc9af1af4af3d1b116426a6ef3c5d0a1e9798bb06a2b27dff632c0de9f668bf546f075aa9ab30e36b237891ef7a3319f8c0fb1172a66060e0a3e4ae65f476c4604d9428fa7e9a5dad6699d0c8326642804fd3f1aa7894c900345f79e3b6be5ce709a9e32687d98313235a640e66c594c01a1fe1bc7aff54579b13fe205c339580e75de2818891fb769fea11177f7032c649a374869885bb9b58c27ede6a349b64c20c21e17ca958eab3447e3cd06744d0ecbea37690560105e5b3936b70f5e9624d88b682760db382003f72563cd82ad424a7aae8b4f1ff6b2061a9a96a9b6dcf7b3966fe128c084ac0d6b2c894e9bc91fd655877fd80f0db8d0a68069bf4cb0e4a79e687a70
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94762);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/24");

  script_cve_id("CVE-2016-6381");
  script_bugtraq_id(93195);
  script_osvdb_id(144897);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy47382");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160928-ios-ikev1");

  script_name(english:"Cisco IOS IKEv1 Fragmentation DoS (cisco-sa-20160928-ios-ikev1)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS software running on the remote device is affected by a denial of
service vulnerability in the Internet Key Exchange version 1 (IKEv1)
subsystem due to improper handling of fragmented IKEv1 packets. An
unauthenticated, remote attacker can exploit this issue, via specially
crafted IKEv1 packets, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-ios-ikev1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30c88959");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuy47382. Alternatively, as a workaround, IKEv2 fragmentation can be
disabled by using the 'no crypto isakmp fragmentation' command.
However, if IKEv1 fragmentation is needed, there is no workaround that
addresses this vulnerability.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;
cmds = make_list();

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Check for vuln version
if ( ver == "12.4(15)T10" ) flag++;
else if ( ver == "12.4(15)T11" ) flag++;
else if ( ver == "12.4(15)T12" ) flag++;
else if ( ver == "12.4(15)T13" ) flag++;
else if ( ver == "12.4(15)T13b" ) flag++;
else if ( ver == "12.4(15)T14" ) flag++;
else if ( ver == "12.4(15)T15" ) flag++;
else if ( ver == "12.4(15)T16" ) flag++;
else if ( ver == "12.4(15)T17" ) flag++;
else if ( ver == "12.4(15)T7" ) flag++;
else if ( ver == "12.4(15)T8" ) flag++;
else if ( ver == "12.4(15)T9" ) flag++;
else if ( ver == "12.4(15)XL4" ) flag++;
else if ( ver == "12.4(15)XL5" ) flag++;
else if ( ver == "12.4(20)MR" ) flag++;
else if ( ver == "12.4(20)MR2" ) flag++;
else if ( ver == "12.4(20)MRB" ) flag++;
else if ( ver == "12.4(20)MRB1" ) flag++;
else if ( ver == "12.4(20)T1" ) flag++;
else if ( ver == "12.4(20)T2" ) flag++;
else if ( ver == "12.4(20)T3" ) flag++;
else if ( ver == "12.4(20)T4" ) flag++;
else if ( ver == "12.4(20)T5" ) flag++;
else if ( ver == "12.4(20)T5a" ) flag++;
else if ( ver == "12.4(20)T6" ) flag++;
else if ( ver == "12.4(22)GC1" ) flag++;
else if ( ver == "12.4(22)GC1a" ) flag++;
else if ( ver == "12.4(22)MD" ) flag++;
else if ( ver == "12.4(22)MD1" ) flag++;
else if ( ver == "12.4(22)MD2" ) flag++;
else if ( ver == "12.4(22)MDA" ) flag++;
else if ( ver == "12.4(22)MDA1" ) flag++;
else if ( ver == "12.4(22)MDA2" ) flag++;
else if ( ver == "12.4(22)MDA3" ) flag++;
else if ( ver == "12.4(22)MDA4" ) flag++;
else if ( ver == "12.4(22)MDA5" ) flag++;
else if ( ver == "12.4(22)MDA6" ) flag++;
else if ( ver == "12.4(22)T" ) flag++;
else if ( ver == "12.4(22)T1" ) flag++;
else if ( ver == "12.4(22)T2" ) flag++;
else if ( ver == "12.4(22)T3" ) flag++;
else if ( ver == "12.4(22)T4" ) flag++;
else if ( ver == "12.4(22)T5" ) flag++;
else if ( ver == "12.4(22)XR1" ) flag++;
else if ( ver == "12.4(22)XR10" ) flag++;
else if ( ver == "12.4(22)XR11" ) flag++;
else if ( ver == "12.4(22)XR12" ) flag++;
else if ( ver == "12.4(22)XR2" ) flag++;
else if ( ver == "12.4(22)XR3" ) flag++;
else if ( ver == "12.4(22)XR4" ) flag++;
else if ( ver == "12.4(22)XR5" ) flag++;
else if ( ver == "12.4(22)XR6" ) flag++;
else if ( ver == "12.4(22)XR7" ) flag++;
else if ( ver == "12.4(22)XR8" ) flag++;
else if ( ver == "12.4(22)XR9" ) flag++;
else if ( ver == "12.4(22)YB" ) flag++;
else if ( ver == "12.4(22)YB1" ) flag++;
else if ( ver == "12.4(22)YB2" ) flag++;
else if ( ver == "12.4(22)YB3" ) flag++;
else if ( ver == "12.4(22)YB4" ) flag++;
else if ( ver == "12.4(22)YB5" ) flag++;
else if ( ver == "12.4(22)YB6" ) flag++;
else if ( ver == "12.4(22)YB7" ) flag++;
else if ( ver == "12.4(22)YB8" ) flag++;
else if ( ver == "12.4(22)YD" ) flag++;
else if ( ver == "12.4(22)YD1" ) flag++;
else if ( ver == "12.4(22)YD2" ) flag++;
else if ( ver == "12.4(22)YD3" ) flag++;
else if ( ver == "12.4(22)YD4" ) flag++;
else if ( ver == "12.4(22)YE" ) flag++;
else if ( ver == "12.4(22)YE1" ) flag++;
else if ( ver == "12.4(22)YE2" ) flag++;
else if ( ver == "12.4(22)YE3" ) flag++;
else if ( ver == "12.4(22)YE4" ) flag++;
else if ( ver == "12.4(22)YE5" ) flag++;
else if ( ver == "12.4(22)YE6" ) flag++;
else if ( ver == "12.4(24)GC1" ) flag++;
else if ( ver == "12.4(24)GC3" ) flag++;
else if ( ver == "12.4(24)GC3a" ) flag++;
else if ( ver == "12.4(24)GC4" ) flag++;
else if ( ver == "12.4(24)GC5" ) flag++;
else if ( ver == "12.4(24)MD" ) flag++;
else if ( ver == "12.4(24)MD1" ) flag++;
else if ( ver == "12.4(24)MD2" ) flag++;
else if ( ver == "12.4(24)MD3" ) flag++;
else if ( ver == "12.4(24)MD4" ) flag++;
else if ( ver == "12.4(24)MD5" ) flag++;
else if ( ver == "12.4(24)MD6" ) flag++;
else if ( ver == "12.4(24)MD7" ) flag++;
else if ( ver == "12.4(24)MDA" ) flag++;
else if ( ver == "12.4(24)MDA1" ) flag++;
else if ( ver == "12.4(24)MDA10" ) flag++;
else if ( ver == "12.4(24)MDA11" ) flag++;
else if ( ver == "12.4(24)MDA12" ) flag++;
else if ( ver == "12.4(24)MDA13" ) flag++;
else if ( ver == "12.4(24)MDA2" ) flag++;
else if ( ver == "12.4(24)MDA3" ) flag++;
else if ( ver == "12.4(24)MDA4" ) flag++;
else if ( ver == "12.4(24)MDA5" ) flag++;
else if ( ver == "12.4(24)MDA6" ) flag++;
else if ( ver == "12.4(24)MDA7" ) flag++;
else if ( ver == "12.4(24)MDA8" ) flag++;
else if ( ver == "12.4(24)MDA9" ) flag++;
else if ( ver == "12.4(24)MDB" ) flag++;
else if ( ver == "12.4(24)MDB1" ) flag++;
else if ( ver == "12.4(24)MDB10" ) flag++;
else if ( ver == "12.4(24)MDB11" ) flag++;
else if ( ver == "12.4(24)MDB12" ) flag++;
else if ( ver == "12.4(24)MDB13" ) flag++;
else if ( ver == "12.4(24)MDB14" ) flag++;
else if ( ver == "12.4(24)MDB15" ) flag++;
else if ( ver == "12.4(24)MDB16" ) flag++;
else if ( ver == "12.4(24)MDB17" ) flag++;
else if ( ver == "12.4(24)MDB18" ) flag++;
else if ( ver == "12.4(24)MDB19" ) flag++;
else if ( ver == "12.4(24)MDB3" ) flag++;
else if ( ver == "12.4(24)MDB4" ) flag++;
else if ( ver == "12.4(24)MDB5" ) flag++;
else if ( ver == "12.4(24)MDB5a" ) flag++;
else if ( ver == "12.4(24)MDB6" ) flag++;
else if ( ver == "12.4(24)MDB7" ) flag++;
else if ( ver == "12.4(24)MDB8" ) flag++;
else if ( ver == "12.4(24)MDB9" ) flag++;
else if ( ver == "12.4(24)T" ) flag++;
else if ( ver == "12.4(24)T1" ) flag++;
else if ( ver == "12.4(24)T10" ) flag++;
else if ( ver == "12.4(24)T11" ) flag++;
else if ( ver == "12.4(24)T12" ) flag++;
else if ( ver == "12.4(24)T2" ) flag++;
else if ( ver == "12.4(24)T3" ) flag++;
else if ( ver == "12.4(24)T3e" ) flag++;
else if ( ver == "12.4(24)T3f" ) flag++;
else if ( ver == "12.4(24)T4" ) flag++;
else if ( ver == "12.4(24)T4a" ) flag++;
else if ( ver == "12.4(24)T4b" ) flag++;
else if ( ver == "12.4(24)T4c" ) flag++;
else if ( ver == "12.4(24)T4d" ) flag++;
else if ( ver == "12.4(24)T4e" ) flag++;
else if ( ver == "12.4(24)T4f" ) flag++;
else if ( ver == "12.4(24)T4g" ) flag++;
else if ( ver == "12.4(24)T4h" ) flag++;
else if ( ver == "12.4(24)T4i" ) flag++;
else if ( ver == "12.4(24)T4j" ) flag++;
else if ( ver == "12.4(24)T4k" ) flag++;
else if ( ver == "12.4(24)T4l" ) flag++;
else if ( ver == "12.4(24)T4m" ) flag++;
else if ( ver == "12.4(24)T4n" ) flag++;
else if ( ver == "12.4(24)T4o" ) flag++;
else if ( ver == "12.4(24)T5" ) flag++;
else if ( ver == "12.4(24)T6" ) flag++;
else if ( ver == "12.4(24)T7" ) flag++;
else if ( ver == "12.4(24)T8" ) flag++;
else if ( ver == "12.4(24)T9" ) flag++;
else if ( ver == "12.4(24)YE" ) flag++;
else if ( ver == "12.4(24)YE1" ) flag++;
else if ( ver == "12.4(24)YE2" ) flag++;
else if ( ver == "12.4(24)YE3" ) flag++;
else if ( ver == "12.4(24)YE3a" ) flag++;
else if ( ver == "12.4(24)YE3b" ) flag++;
else if ( ver == "12.4(24)YE3c" ) flag++;
else if ( ver == "12.4(24)YE3d" ) flag++;
else if ( ver == "12.4(24)YE3e" ) flag++;
else if ( ver == "12.4(24)YE4" ) flag++;
else if ( ver == "12.4(24)YE5" ) flag++;
else if ( ver == "12.4(24)YE6" ) flag++;
else if ( ver == "12.4(24)YE7" ) flag++;
else if ( ver == "12.4(24)YG1" ) flag++;
else if ( ver == "12.4(24)YG2" ) flag++;
else if ( ver == "12.4(24)YG3" ) flag++;
else if ( ver == "12.4(24)YG4" ) flag++;
else if ( ver == "12.4(24)YS" ) flag++;
else if ( ver == "12.4(24)YS1" ) flag++;
else if ( ver == "12.4(24)YS10" ) flag++;
else if ( ver == "12.4(24)YS2" ) flag++;
else if ( ver == "12.4(24)YS3" ) flag++;
else if ( ver == "12.4(24)YS4" ) flag++;
else if ( ver == "12.4(24)YS5" ) flag++;
else if ( ver == "12.4(24)YS6" ) flag++;
else if ( ver == "12.4(24)YS7" ) flag++;
else if ( ver == "12.4(24)YS8" ) flag++;
else if ( ver == "12.4(24)YS8a" ) flag++;
else if ( ver == "12.4(24)YS9" ) flag++;
else if ( ver == "15.0(1)M" ) flag++;
else if ( ver == "15.0(1)M1" ) flag++;
else if ( ver == "15.0(1)M10" ) flag++;
else if ( ver == "15.0(1)M2" ) flag++;
else if ( ver == "15.0(1)M3" ) flag++;
else if ( ver == "15.0(1)M4" ) flag++;
else if ( ver == "15.0(1)M5" ) flag++;
else if ( ver == "15.0(1)M6" ) flag++;
else if ( ver == "15.0(1)M6a" ) flag++;
else if ( ver == "15.0(1)M7" ) flag++;
else if ( ver == "15.0(1)M8" ) flag++;
else if ( ver == "15.0(1)M9" ) flag++;
else if ( ver == "15.0(1)MR" ) flag++;
else if ( ver == "15.0(1)S" ) flag++;
else if ( ver == "15.0(1)S1" ) flag++;
else if ( ver == "15.0(1)S2" ) flag++;
else if ( ver == "15.0(1)S3a" ) flag++;
else if ( ver == "15.0(1)S4" ) flag++;
else if ( ver == "15.0(1)S4a" ) flag++;
else if ( ver == "15.0(1)S5" ) flag++;
else if ( ver == "15.0(1)S6" ) flag++;
else if ( ver == "15.0(1)XA" ) flag++;
else if ( ver == "15.0(1)XA1" ) flag++;
else if ( ver == "15.0(1)XA2" ) flag++;
else if ( ver == "15.0(1)XA3" ) flag++;
else if ( ver == "15.0(1)XA4" ) flag++;
else if ( ver == "15.0(1)XA5" ) flag++;
else if ( ver == "15.0(2a)EX5" ) flag++;
else if ( ver == "15.0(2a)SE9" ) flag++;
else if ( ver == "15.0(2)EB" ) flag++;
else if ( ver == "15.0(2)EC" ) flag++;
else if ( ver == "15.0(2)ED" ) flag++;
else if ( ver == "15.0(2)ED1" ) flag++;
else if ( ver == "15.0(2)EH" ) flag++;
else if ( ver == "15.0(2)EJ" ) flag++;
else if ( ver == "15.0(2)EJ1" ) flag++;
else if ( ver == "15.0(2)EK" ) flag++;
else if ( ver == "15.0(2)EK1" ) flag++;
else if ( ver == "15.0(2)EX" ) flag++;
else if ( ver == "15.0(2)EX1" ) flag++;
else if ( ver == "15.0(2)EX10" ) flag++;
else if ( ver == "15.0(2)EX2" ) flag++;
else if ( ver == "15.0(2)EX3" ) flag++;
else if ( ver == "15.0(2)EX4" ) flag++;
else if ( ver == "15.0(2)EX5" ) flag++;
else if ( ver == "15.0(2)EX6" ) flag++;
else if ( ver == "15.0(2)EX7" ) flag++;
else if ( ver == "15.0(2)EX8" ) flag++;
else if ( ver == "15.0(2)EY" ) flag++;
else if ( ver == "15.0(2)EY1" ) flag++;
else if ( ver == "15.0(2)EY2" ) flag++;
else if ( ver == "15.0(2)EY3" ) flag++;
else if ( ver == "15.0(2)EZ" ) flag++;
else if ( ver == "15.0(2)MR" ) flag++;
else if ( ver == "15.0(2)SE" ) flag++;
else if ( ver == "15.0(2)SE1" ) flag++;
else if ( ver == "15.0(2)SE2" ) flag++;
else if ( ver == "15.0(2)SE3" ) flag++;
else if ( ver == "15.0(2)SE4" ) flag++;
else if ( ver == "15.0(2)SE5" ) flag++;
else if ( ver == "15.0(2)SE6" ) flag++;
else if ( ver == "15.0(2)SE7" ) flag++;
else if ( ver == "15.0(2)SE9" ) flag++;
else if ( ver == "15.1(1)MR" ) flag++;
else if ( ver == "15.1(1)MR1" ) flag++;
else if ( ver == "15.1(1)MR2" ) flag++;
else if ( ver == "15.1(1)MR3" ) flag++;
else if ( ver == "15.1(1)MR4" ) flag++;
else if ( ver == "15.1(1)MR5" ) flag++;
else if ( ver == "15.1(1)MR6" ) flag++;
else if ( ver == "15.1(1)S" ) flag++;
else if ( ver == "15.1(1)S1" ) flag++;
else if ( ver == "15.1(1)S2" ) flag++;
else if ( ver == "15.1(1)SA" ) flag++;
else if ( ver == "15.1(1)SA1" ) flag++;
else if ( ver == "15.1(1)SA2" ) flag++;
else if ( ver == "15.1(1)SG" ) flag++;
else if ( ver == "15.1(1)SG1" ) flag++;
else if ( ver == "15.1(1)SG2" ) flag++;
else if ( ver == "15.1(1)SY" ) flag++;
else if ( ver == "15.1(1)SY1" ) flag++;
else if ( ver == "15.1(1)SY2" ) flag++;
else if ( ver == "15.1(1)SY3" ) flag++;
else if ( ver == "15.1(1)SY4" ) flag++;
else if ( ver == "15.1(1)SY5" ) flag++;
else if ( ver == "15.1(1)SY6" ) flag++;
else if ( ver == "15.1(1)T" ) flag++;
else if ( ver == "15.1(1)T1" ) flag++;
else if ( ver == "15.1(1)T2" ) flag++;
else if ( ver == "15.1(1)T3" ) flag++;
else if ( ver == "15.1(1)T4" ) flag++;
else if ( ver == "15.1(1)T5" ) flag++;
else if ( ver == "15.1(1)XB" ) flag++;
else if ( ver == "15.1(1)XB1" ) flag++;
else if ( ver == "15.1(1)XB2" ) flag++;
else if ( ver == "15.1(1)XB3" ) flag++;
else if ( ver == "15.1(2)EY" ) flag++;
else if ( ver == "15.1(2)EY1" ) flag++;
else if ( ver == "15.1(2)EY1a" ) flag++;
else if ( ver == "15.1(2)EY2" ) flag++;
else if ( ver == "15.1(2)EY2a" ) flag++;
else if ( ver == "15.1(2)EY3" ) flag++;
else if ( ver == "15.1(2)EY4" ) flag++;
else if ( ver == "15.1(2)GC" ) flag++;
else if ( ver == "15.1(2)GC1" ) flag++;
else if ( ver == "15.1(2)GC2" ) flag++;
else if ( ver == "15.1(2)S" ) flag++;
else if ( ver == "15.1(2)S1" ) flag++;
else if ( ver == "15.1(2)S2" ) flag++;
else if ( ver == "15.1(2)SG" ) flag++;
else if ( ver == "15.1(2)SG1" ) flag++;
else if ( ver == "15.1(2)SG2" ) flag++;
else if ( ver == "15.1(2)SG3" ) flag++;
else if ( ver == "15.1(2)SG4" ) flag++;
else if ( ver == "15.1(2)SG5" ) flag++;
else if ( ver == "15.1(2)SG6" ) flag++;
else if ( ver == "15.1(2)SG7" ) flag++;
else if ( ver == "15.1(2)SNG" ) flag++;
else if ( ver == "15.1(2)SNH" ) flag++;
else if ( ver == "15.1(2)SNH1" ) flag++;
else if ( ver == "15.1(2)SNI" ) flag++;
else if ( ver == "15.1(2)SNI1" ) flag++;
else if ( ver == "15.1(2)SY" ) flag++;
else if ( ver == "15.1(2)SY1" ) flag++;
else if ( ver == "15.1(2)SY2" ) flag++;
else if ( ver == "15.1(2)SY3" ) flag++;
else if ( ver == "15.1(2)SY4" ) flag++;
else if ( ver == "15.1(2)SY4a" ) flag++;
else if ( ver == "15.1(2)SY5" ) flag++;
else if ( ver == "15.1(2)SY6" ) flag++;
else if ( ver == "15.1(2)SY7" ) flag++;
else if ( ver == "15.1(2)T" ) flag++;
else if ( ver == "15.1(2)T0a" ) flag++;
else if ( ver == "15.1(2)T1" ) flag++;
else if ( ver == "15.1(2)T2" ) flag++;
else if ( ver == "15.1(2)T2a" ) flag++;
else if ( ver == "15.1(2)T3" ) flag++;
else if ( ver == "15.1(2)T4" ) flag++;
else if ( ver == "15.1(2)T5" ) flag++;
else if ( ver == "15.1(3)MR" ) flag++;
else if ( ver == "15.1(3)MRA" ) flag++;
else if ( ver == "15.1(3)MRA1" ) flag++;
else if ( ver == "15.1(3)MRA2" ) flag++;
else if ( ver == "15.1(3)MRA3" ) flag++;
else if ( ver == "15.1(3)MRA4" ) flag++;
else if ( ver == "15.1(3)S" ) flag++;
else if ( ver == "15.1(3)S0a" ) flag++;
else if ( ver == "15.1(3)S1" ) flag++;
else if ( ver == "15.1(3)S2" ) flag++;
else if ( ver == "15.1(3)S3" ) flag++;
else if ( ver == "15.1(3)S4" ) flag++;
else if ( ver == "15.1(3)S5" ) flag++;
else if ( ver == "15.1(3)S5a" ) flag++;
else if ( ver == "15.1(3)S6" ) flag++;
else if ( ver == "15.1(3)S7" ) flag++;
else if ( ver == "15.1(3)SVB1" ) flag++;
else if ( ver == "15.1(3)SVD" ) flag++;
else if ( ver == "15.1(3)SVD1" ) flag++;
else if ( ver == "15.1(3)SVD2" ) flag++;
else if ( ver == "15.1(3)SVD3" ) flag++;
else if ( ver == "15.1(3)SVE" ) flag++;
else if ( ver == "15.1(3)SVF" ) flag++;
else if ( ver == "15.1(3)SVF1" ) flag++;
else if ( ver == "15.1(3)SVF2" ) flag++;
else if ( ver == "15.1(3)SVF2a" ) flag++;
else if ( ver == "15.1(3)SVF4a" ) flag++;
else if ( ver == "15.1(3)SVF4b" ) flag++;
else if ( ver == "15.1(3)SVF4d" ) flag++;
else if ( ver == "15.1(3)SVG1c" ) flag++;
else if ( ver == "15.1(3)SVG2" ) flag++;
else if ( ver == "15.1(3)SVG2a" ) flag++;
else if ( ver == "15.1(3)SVG3" ) flag++;
else if ( ver == "15.1(3)SVG3a" ) flag++;
else if ( ver == "15.1(3)SVG3b" ) flag++;
else if ( ver == "15.1(3)SVG3c" ) flag++;
else if ( ver == "15.1(3)SVH" ) flag++;
else if ( ver == "15.1(3)SVH2" ) flag++;
else if ( ver == "15.1(3)SVH4" ) flag++;
else if ( ver == "15.1(3)SVI" ) flag++;
else if ( ver == "15.1(3)SVI1" ) flag++;
else if ( ver == "15.1(3)SVI1a" ) flag++;
else if ( ver == "15.1(3)SVI2" ) flag++;
else if ( ver == "15.1(3)T" ) flag++;
else if ( ver == "15.1(3)T1" ) flag++;
else if ( ver == "15.1(3)T2" ) flag++;
else if ( ver == "15.1(3)T3" ) flag++;
else if ( ver == "15.1(3)T4" ) flag++;
else if ( ver == "15.1(4)GC" ) flag++;
else if ( ver == "15.1(4)GC1" ) flag++;
else if ( ver == "15.1(4)GC2" ) flag++;
else if ( ver == "15.1(4)M" ) flag++;
else if ( ver == "15.1(4)M0a" ) flag++;
else if ( ver == "15.1(4)M0b" ) flag++;
else if ( ver == "15.1(4)M1" ) flag++;
else if ( ver == "15.1(4)M10" ) flag++;
else if ( ver == "15.1(4)M11" ) flag++;
else if ( ver == "15.1(4)M12" ) flag++;
else if ( ver == "15.1(4)M12a" ) flag++;
else if ( ver == "15.1(4)M2" ) flag++;
else if ( ver == "15.1(4)M3" ) flag++;
else if ( ver == "15.1(4)M3a" ) flag++;
else if ( ver == "15.1(4)M4" ) flag++;
else if ( ver == "15.1(4)M5" ) flag++;
else if ( ver == "15.1(4)M6" ) flag++;
else if ( ver == "15.1(4)M7" ) flag++;
else if ( ver == "15.1(4)M8" ) flag++;
else if ( ver == "15.1(4)M9" ) flag++;
else if ( ver == "15.1(4)XB4" ) flag++;
else if ( ver == "15.1(4)XB5" ) flag++;
else if ( ver == "15.1(4)XB5a" ) flag++;
else if ( ver == "15.1(4)XB6" ) flag++;
else if ( ver == "15.1(4)XB7" ) flag++;
else if ( ver == "15.1(4)XB8" ) flag++;
else if ( ver == "15.1(4)XB8a" ) flag++;
else if ( ver == "15.2(1)E" ) flag++;
else if ( ver == "15.2(1)E1" ) flag++;
else if ( ver == "15.2(1)E2" ) flag++;
else if ( ver == "15.2(1)E3" ) flag++;
else if ( ver == "15.2(1)EY" ) flag++;
else if ( ver == "15.2(1)EY1" ) flag++;
else if ( ver == "15.2(1)EY2" ) flag++;
else if ( ver == "15.2(1)GC" ) flag++;
else if ( ver == "15.2(1)GC1" ) flag++;
else if ( ver == "15.2(1)GC2" ) flag++;
else if ( ver == "15.2(1)S" ) flag++;
else if ( ver == "15.2(1)S1" ) flag++;
else if ( ver == "15.2(1)S2" ) flag++;
else if ( ver == "15.2(1)SC1a" ) flag++;
else if ( ver == "15.2(1)SC2" ) flag++;
else if ( ver == "15.2(1)SD1" ) flag++;
else if ( ver == "15.2(1)SD2" ) flag++;
else if ( ver == "15.2(1)SD3" ) flag++;
else if ( ver == "15.2(1)SD4" ) flag++;
else if ( ver == "15.2(1)SD6" ) flag++;
else if ( ver == "15.2(1)SD6a" ) flag++;
else if ( ver == "15.2(1)SD8" ) flag++;
else if ( ver == "15.2(1)SY" ) flag++;
else if ( ver == "15.2(1)SY0a" ) flag++;
else if ( ver == "15.2(1)SY1" ) flag++;
else if ( ver == "15.2(1)SY1a" ) flag++;
else if ( ver == "15.2(1)SY2" ) flag++;
else if ( ver == "15.2(1)T" ) flag++;
else if ( ver == "15.2(1)T1" ) flag++;
else if ( ver == "15.2(1)T2" ) flag++;
else if ( ver == "15.2(1)T3" ) flag++;
else if ( ver == "15.2(1)T3a" ) flag++;
else if ( ver == "15.2(1)T4" ) flag++;
else if ( ver == "15.2(2a)E1" ) flag++;
else if ( ver == "15.2(2b)E" ) flag++;
else if ( ver == "15.2(2)E" ) flag++;
else if ( ver == "15.2(2)E1" ) flag++;
else if ( ver == "15.2(2)E2" ) flag++;
else if ( ver == "15.2(2)E4" ) flag++;
else if ( ver == "15.2(2)EA1" ) flag++;
else if ( ver == "15.2(2)EA2" ) flag++;
else if ( ver == "15.2(2)EA3" ) flag++;
else if ( ver == "15.2(2)EB" ) flag++;
else if ( ver == "15.2(2)EB1" ) flag++;
else if ( ver == "15.2(2)EB2" ) flag++;
else if ( ver == "15.2(2)GC" ) flag++;
else if ( ver == "15.2(2)JA" ) flag++;
else if ( ver == "15.2(2)JA1" ) flag++;
else if ( ver == "15.2(2)JAX" ) flag++;
else if ( ver == "15.2(2)JAX1" ) flag++;
else if ( ver == "15.2(2)JB" ) flag++;
else if ( ver == "15.2(2)JB1" ) flag++;
else if ( ver == "15.2(2)JB2" ) flag++;
else if ( ver == "15.2(2)JB3" ) flag++;
else if ( ver == "15.2(2)JB4" ) flag++;
else if ( ver == "15.2(2)JB5" ) flag++;
else if ( ver == "15.2(2)JN1" ) flag++;
else if ( ver == "15.2(2)JN2" ) flag++;
else if ( ver == "15.2(2)S" ) flag++;
else if ( ver == "15.2(2)S0a" ) flag++;
else if ( ver == "15.2(2)S0c" ) flag++;
else if ( ver == "15.2(2)S0d" ) flag++;
else if ( ver == "15.2(2)S1" ) flag++;
else if ( ver == "15.2(2)S2" ) flag++;
else if ( ver == "15.2(2)SC" ) flag++;
else if ( ver == "15.2(2)SNG" ) flag++;
else if ( ver == "15.2(2)SNH" ) flag++;
else if ( ver == "15.2(2)SNH1" ) flag++;
else if ( ver == "15.2(2)SNI" ) flag++;
else if ( ver == "15.2(2)SY" ) flag++;
else if ( ver == "15.2(2)SY1" ) flag++;
else if ( ver == "15.2(2)T" ) flag++;
else if ( ver == "15.2(2)T1" ) flag++;
else if ( ver == "15.2(2)T2" ) flag++;
else if ( ver == "15.2(2)T3" ) flag++;
else if ( ver == "15.2(2)T4" ) flag++;
else if ( ver == "15.2(3a)E" ) flag++;
else if ( ver == "15.2(3)E" ) flag++;
else if ( ver == "15.2(3)E1" ) flag++;
else if ( ver == "15.2(3)E2" ) flag++;
else if ( ver == "15.2(3)E3" ) flag++;
else if ( ver == "15.2(3)EA" ) flag++;
else if ( ver == "15.2(3)GC" ) flag++;
else if ( ver == "15.2(3)GC1" ) flag++;
else if ( ver == "15.2(3)GCA" ) flag++;
else if ( ver == "15.2(3)GCA1" ) flag++;
else if ( ver == "15.2(3m)E2" ) flag++;
else if ( ver == "15.2(3m)E3" ) flag++;
else if ( ver == "15.2(3m)E5" ) flag++;
else if ( ver == "15.2(3m)E7" ) flag++;
else if ( ver == "15.2(3m)E8" ) flag++;
else if ( ver == "15.2(3)T" ) flag++;
else if ( ver == "15.2(3)T1" ) flag++;
else if ( ver == "15.2(3)T2" ) flag++;
else if ( ver == "15.2(3)T3" ) flag++;
else if ( ver == "15.2(3)T4" ) flag++;
else if ( ver == "15.2(3)XA" ) flag++;
else if ( ver == "15.2(4)E" ) flag++;
else if ( ver == "15.2(4)E1" ) flag++;
else if ( ver == "15.2(4)EA" ) flag++;
else if ( ver == "15.2(4)EA1" ) flag++;
else if ( ver == "15.2(4)EA2" ) flag++;
else if ( ver == "15.2(4)EA3" ) flag++;
else if ( ver == "15.2(4)GC" ) flag++;
else if ( ver == "15.2(4)GC1" ) flag++;
else if ( ver == "15.2(4)GC2" ) flag++;
else if ( ver == "15.2(4)GC3" ) flag++;
else if ( ver == "15.2(4)JA" ) flag++;
else if ( ver == "15.2(4)JA1" ) flag++;
else if ( ver == "15.2(4)JAZ" ) flag++;
else if ( ver == "15.2(4)JB" ) flag++;
else if ( ver == "15.2(4)JB1" ) flag++;
else if ( ver == "15.2(4)JB2" ) flag++;
else if ( ver == "15.2(4)JB3" ) flag++;
else if ( ver == "15.2(4)JB3a" ) flag++;
else if ( ver == "15.2(4)JB3b" ) flag++;
else if ( ver == "15.2(4)JB3h" ) flag++;
else if ( ver == "15.2(4)JB3s" ) flag++;
else if ( ver == "15.2(4)JB4" ) flag++;
else if ( ver == "15.2(4)JB5" ) flag++;
else if ( ver == "15.2(4)JB50" ) flag++;
else if ( ver == "15.2(4)JB50a" ) flag++;
else if ( ver == "15.2(4)JB5h" ) flag++;
else if ( ver == "15.2(4)JB5m" ) flag++;
else if ( ver == "15.2(4)JB6" ) flag++;
else if ( ver == "15.2(4)JB7" ) flag++;
else if ( ver == "15.2(4)JN" ) flag++;
else if ( ver == "15.2(4)M" ) flag++;
else if ( ver == "15.2(4)M1" ) flag++;
else if ( ver == "15.2(4)M10" ) flag++;
else if ( ver == "15.2(4)M11" ) flag++;
else if ( ver == "15.2(4)M2" ) flag++;
else if ( ver == "15.2(4)M3" ) flag++;
else if ( ver == "15.2(4)M4" ) flag++;
else if ( ver == "15.2(4)M5" ) flag++;
else if ( ver == "15.2(4)M6" ) flag++;
else if ( ver == "15.2(4)M6a" ) flag++;
else if ( ver == "15.2(4)M6b" ) flag++;
else if ( ver == "15.2(4)M7" ) flag++;
else if ( ver == "15.2(4)M8" ) flag++;
else if ( ver == "15.2(4)M9" ) flag++;
else if ( ver == "15.2(4m)E1" ) flag++;
else if ( ver == "15.2(4)S" ) flag++;
else if ( ver == "15.2(4)S0c" ) flag++;
else if ( ver == "15.2(4)S1" ) flag++;
else if ( ver == "15.2(4)S1c" ) flag++;
else if ( ver == "15.2(4)S2" ) flag++;
else if ( ver == "15.2(4)S3" ) flag++;
else if ( ver == "15.2(4)S3a" ) flag++;
else if ( ver == "15.2(4)S4" ) flag++;
else if ( ver == "15.2(4)S4a" ) flag++;
else if ( ver == "15.2(4)S5" ) flag++;
else if ( ver == "15.2(4)S6" ) flag++;
else if ( ver == "15.2(4)S7" ) flag++;
else if ( ver == "15.2(4)S8" ) flag++;
else if ( ver == "15.2(4)XB10" ) flag++;
else if ( ver == "15.2(4)XB11" ) flag++;
else if ( ver == "15.3(0)SY" ) flag++;
else if ( ver == "15.3(1)S" ) flag++;
else if ( ver == "15.3(1)S1" ) flag++;
else if ( ver == "15.3(1)S1e" ) flag++;
else if ( ver == "15.3(1)S2" ) flag++;
else if ( ver == "15.3(1)SY" ) flag++;
else if ( ver == "15.3(1)T" ) flag++;
else if ( ver == "15.3(1)T1" ) flag++;
else if ( ver == "15.3(1)T2" ) flag++;
else if ( ver == "15.3(1)T3" ) flag++;
else if ( ver == "15.3(1)T4" ) flag++;
else if ( ver == "15.3(2)S" ) flag++;
else if ( ver == "15.3(2)S0a" ) flag++;
else if ( ver == "15.3(2)S1" ) flag++;
else if ( ver == "15.3(2)S2" ) flag++;
else if ( ver == "15.3(2)T" ) flag++;
else if ( ver == "15.3(2)T1" ) flag++;
else if ( ver == "15.3(2)T2" ) flag++;
else if ( ver == "15.3(2)T3" ) flag++;
else if ( ver == "15.3(2)T4" ) flag++;
else if ( ver == "15.3(3)JA" ) flag++;
else if ( ver == "15.3(3)JA1" ) flag++;
else if ( ver == "15.3(3)JA100" ) flag++;
else if ( ver == "15.3(3)JA1m" ) flag++;
else if ( ver == "15.3(3)JA1n" ) flag++;
else if ( ver == "15.3(3)JA2" ) flag++;
else if ( ver == "15.3(3)JA3" ) flag++;
else if ( ver == "15.3(3)JA4" ) flag++;
else if ( ver == "15.3(3)JA5" ) flag++;
else if ( ver == "15.3(3)JA6" ) flag++;
else if ( ver == "15.3(3)JA7" ) flag++;
else if ( ver == "15.3(3)JA75" ) flag++;
else if ( ver == "15.3(3)JA77" ) flag++;
else if ( ver == "15.3(3)JA8" ) flag++;
else if ( ver == "15.3(3)JA9" ) flag++;
else if ( ver == "15.3(3)JAA" ) flag++;
else if ( ver == "15.3(3)JAB" ) flag++;
else if ( ver == "15.3(3)JAX" ) flag++;
else if ( ver == "15.3(3)JAX1" ) flag++;
else if ( ver == "15.3(3)JAX2" ) flag++;
else if ( ver == "15.3(3)JB" ) flag++;
else if ( ver == "15.3(3)JB75" ) flag++;
else if ( ver == "15.3(3)JBB" ) flag++;
else if ( ver == "15.3(3)JBB1" ) flag++;
else if ( ver == "15.3(3)JBB2" ) flag++;
else if ( ver == "15.3(3)JBB4" ) flag++;
else if ( ver == "15.3(3)JBB5" ) flag++;
else if ( ver == "15.3(3)JBB50" ) flag++;
else if ( ver == "15.3(3)JBB6" ) flag++;
else if ( ver == "15.3(3)JBB6a" ) flag++;
else if ( ver == "15.3(3)JBB8" ) flag++;
else if ( ver == "15.3(3)JC" ) flag++;
else if ( ver == "15.3(3)JC30" ) flag++;
else if ( ver == "15.3(3)JN3" ) flag++;
else if ( ver == "15.3(3)JN4" ) flag++;
else if ( ver == "15.3(3)JN6" ) flag++;
else if ( ver == "15.3(3)JN7" ) flag++;
else if ( ver == "15.3(3)JN8" ) flag++;
else if ( ver == "15.3(3)JNB" ) flag++;
else if ( ver == "15.3(3)JNB1" ) flag++;
else if ( ver == "15.3(3)JNB2" ) flag++;
else if ( ver == "15.3(3)JNB3" ) flag++;
else if ( ver == "15.3(3)JNC" ) flag++;
else if ( ver == "15.3(3)JNC1" ) flag++;
else if ( ver == "15.3(3)JNP" ) flag++;
else if ( ver == "15.3(3)JNP1" ) flag++;
else if ( ver == "15.3(3)M" ) flag++;
else if ( ver == "15.3(3)M1" ) flag++;
else if ( ver == "15.3(3)M2" ) flag++;
else if ( ver == "15.3(3)M3" ) flag++;
else if ( ver == "15.3(3)M4" ) flag++;
else if ( ver == "15.3(3)M5" ) flag++;
else if ( ver == "15.3(3)M6" ) flag++;
else if ( ver == "15.3(3)M7" ) flag++;
else if ( ver == "15.3(3)S" ) flag++;
else if ( ver == "15.3(3)S1" ) flag++;
else if ( ver == "15.3(3)S1a" ) flag++;
else if ( ver == "15.3(3)S2" ) flag++;
else if ( ver == "15.3(3)S2a" ) flag++;
else if ( ver == "15.3(3)S3" ) flag++;
else if ( ver == "15.3(3)S4" ) flag++;
else if ( ver == "15.3(3)S5" ) flag++;
else if ( ver == "15.3(3)S6" ) flag++;
else if ( ver == "15.3(3)S6a" ) flag++;
else if ( ver == "15.3(3)S7" ) flag++;
else if ( ver == "15.3(3)XB12" ) flag++;
else if ( ver == "15.4(1)CG" ) flag++;
else if ( ver == "15.4(1)CG1" ) flag++;
else if ( ver == "15.4(1)S" ) flag++;
else if ( ver == "15.4(1)S1" ) flag++;
else if ( ver == "15.4(1)S2" ) flag++;
else if ( ver == "15.4(1)S3" ) flag++;
else if ( ver == "15.4(1)S4" ) flag++;
else if ( ver == "15.4(1)T" ) flag++;
else if ( ver == "15.4(1)T1" ) flag++;
else if ( ver == "15.4(1)T2" ) flag++;
else if ( ver == "15.4(1)T3" ) flag++;
else if ( ver == "15.4(1)T4" ) flag++;
else if ( ver == "15.4(2)CG" ) flag++;
else if ( ver == "15.4(2)S" ) flag++;
else if ( ver == "15.4(2)S1" ) flag++;
else if ( ver == "15.4(2)S2" ) flag++;
else if ( ver == "15.4(2)S3" ) flag++;
else if ( ver == "15.4(2)S4" ) flag++;
else if ( ver == "15.4(2)SN" ) flag++;
else if ( ver == "15.4(2)SN1" ) flag++;
else if ( ver == "15.4(2)T" ) flag++;
else if ( ver == "15.4(2)T1" ) flag++;
else if ( ver == "15.4(2)T2" ) flag++;
else if ( ver == "15.4(2)T3" ) flag++;
else if ( ver == "15.4(2)T4" ) flag++;
else if ( ver == "15.4(3)M" ) flag++;
else if ( ver == "15.4(3)M1" ) flag++;
else if ( ver == "15.4(3)M2" ) flag++;
else if ( ver == "15.4(3)M3" ) flag++;
else if ( ver == "15.4(3)M4" ) flag++;
else if ( ver == "15.4(3)M5" ) flag++;
else if ( ver == "15.4(3)S" ) flag++;
else if ( ver == "15.4(3)S0d" ) flag++;
else if ( ver == "15.4(3)S0e" ) flag++;
else if ( ver == "15.4(3)S1" ) flag++;
else if ( ver == "15.4(3)S2" ) flag++;
else if ( ver == "15.4(3)S3" ) flag++;
else if ( ver == "15.4(3)S4" ) flag++;
else if ( ver == "15.4(3)S5" ) flag++;
else if ( ver == "15.4(3)SN1" ) flag++;
else if ( ver == "15.5(1)S" ) flag++;
else if ( ver == "15.5(1)S1" ) flag++;
else if ( ver == "15.5(1)S2" ) flag++;
else if ( ver == "15.5(1)S3" ) flag++;
else if ( ver == "15.5(1)SN" ) flag++;
else if ( ver == "15.5(1)SN1" ) flag++;
else if ( ver == "15.5(1)T" ) flag++;
else if ( ver == "15.5(1)T1" ) flag++;
else if ( ver == "15.5(1)T2" ) flag++;
else if ( ver == "15.5(1)T3" ) flag++;
else if ( ver == "15.5(1)T4" ) flag++;
else if ( ver == "15.5(2)S" ) flag++;
else if ( ver == "15.5(2)S1" ) flag++;
else if ( ver == "15.5(2)S2" ) flag++;
else if ( ver == "15.5(2)S3" ) flag++;
else if ( ver == "15.5(2)SN" ) flag++;
else if ( ver == "15.5(2)SN0a" ) flag++;
else if ( ver == "15.5(2)T" ) flag++;
else if ( ver == "15.5(2)T1" ) flag++;
else if ( ver == "15.5(2)T2" ) flag++;
else if ( ver == "15.5(2)T3" ) flag++;
else if ( ver == "15.5(2)T4" ) flag++;
else if ( ver == "15.5(2)XB" ) flag++;
else if ( ver == "15.5(3)M" ) flag++;
else if ( ver == "15.5(3)M0a" ) flag++;
else if ( ver == "15.5(3)M1" ) flag++;
else if ( ver == "15.5(3)M2" ) flag++;
else if ( ver == "15.5(3)M2a" ) flag++;
else if ( ver == "15.5(3)S" ) flag++;
else if ( ver == "15.5(3)S0a" ) flag++;
else if ( ver == "15.5(3)S1" ) flag++;
else if ( ver == "15.5(3)S1a" ) flag++;
else if ( ver == "15.5(3)S2" ) flag++;
else if ( ver == "15.5(3)SN" ) flag++;
else if ( ver == "15.5(3)SN0a" ) flag++;
else if ( ver == "15.6(1)S" ) flag++;
else if ( ver == "15.6(1)S1" ) flag++;
else if ( ver == "15.6(1)SN" ) flag++;
else if ( ver == "15.6(1)SN1" ) flag++;
else if ( ver == "15.6(1)T" ) flag++;
else if ( ver == "15.6(1)T0a" ) flag++;
else if ( ver == "15.6(1)T1" ) flag++;
else if ( ver == "15.6(2)S" ) flag++;
else if ( ver == "15.6(2)SN" ) flag++;

if(!flag)
  audit(AUDIT_INST_VER_NOT_VULN, ver);

# Check that IKEv1 config or IKEv1 is running
if (get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;

  # Check for condition 1, IKEv1 config
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config","show running-config");
  if (check_cisco_result(buf))
  {
    if ( "crypto isakmp fragmentation" >< buf )
    {
      flag = 1;
      cmds = make_list('show running-config');
    }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }

  # Check for condition 2, IKEv1 is running
  if (flag)
  {
    flag = 0;

    pat = "(\d+.\d+.\d+.\d+|.*:.*|UNKNOWN|--any--)\s+(500|4500)\s";
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_sockets","show ip sockets");
    if (!flag)
    {
      if (check_cisco_result(buf))
      {
        if (preg(multiline:TRUE, pattern:pat, string:buf)) 
        {
          flag = 1;
          cmds = make_list(cmds, 'show ip sockets');
        }
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
        if (preg(multiline:TRUE, pattern:pat, string:buf))
        {
          flag = 1;
          cmds = make_list(cmds, 'show udp');
        }
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
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : 'CSCuy47382',
    cmds     : cmds
  );
}
else audit(AUDIT_HOST_NOT, "affected");
