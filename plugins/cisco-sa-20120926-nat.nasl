#TRUSTED 2e519edced8fc26fbe34147ff0ec015b84dd4640cbee7852821ce63a7c044bce3e141fdacd2142495042e97db1020d87bb9e310162e8f539b73f6fd92855dacd1396e1efb2efb2c1009f39ac57fed56b22fdfe01a80b403a618b52f3518d4efcceb29db25ddbddeca48ec29c61c4490d01bca8f56a2be860b5b2300b9c3799ce7ce6184d4721de60e1df0e6232f4f4c328412896670f036ac2df36da344a4b312c02d066b06fdc5c46afbda267c58aa584d5c88867e262bfefd221cd4ba488f6d5e5b94f428ab322ee5493aea5af13f660cf6c780e51d68d9998c116fc08dede9168ae5bee5dfa8f74125e58810cba01b11972ea1deb1e056e63880cd87dddbc1bbca9b2a75b012cfd828d1dc2ee3c7e0b0ce9028502c2e9772f4f898c3b79d13162c8029a10e85159e00bb09b156e6f8bf9607b3b3efdd3b7a065d57e93256840359ec22d22eeff1488a4dcc223dd005bbb0b368b494d596fbfbbe2a0a12b430979621f8e9845a141fa537b1bf399ceb3436a8f91c57b6dd1214ad596c3244102e559cd2870af3ab2d24293eec7dc0b415d5a0d50b5a9096ee818198c2d836822caafdda6f2e6c8d4eb8724d1f36c5d2b5af8dda437bb56cadbb774e87a76418789d76ee41d2d03cbb70b15e93cdf3e10ab036d71fd1afdb641bcd5732bf8a21c56436c50bc9cd6223e167dabd0a0ac6e8b5fa0c0eb4d97e1f0a92159449088
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20120926-nat.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(62375);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/03");

  script_cve_id("CVE-2012-4618", "CVE-2012-4619");
  script_bugtraq_id(55693, 55705);
  script_osvdb_id(85813);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtn76183");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtr46123");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120926-nat");

  script_name(english:"Cisco IOS Software Network Address Translation Vulnerabilities (cisco-sa-20120926-nat)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Cisco IOS Software Network Address Translation (NAT) feature
contains two denial of service (DoS) vulnerabilities in the
translation of IP packets. The vulnerabilities are caused when packets
in transit on the vulnerable device require translation. Cisco has
released free software updates that address these vulnerabilities."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120926-nat
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4bdbbb81"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20120926-nat."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/28");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if ( version == '12.2(33)SXH7w' ) flag++;
if ( version == '12.2(33)SXH8' ) flag++;
if ( version == '12.2(33)SXH8a' ) flag++;
if ( version == '12.2(33)SXH8b' ) flag++;
if ( version == '12.2(33)SXI5' ) flag++;
if ( version == '12.2(33)SXI5a' ) flag++;
if ( version == '12.2(33)SXI6' ) flag++;
if ( version == '12.2(33)SXJ' ) flag++;
if ( version == '12.2(50)SY' ) flag++;
if ( version == '12.2(50)SY1' ) flag++;
if ( version == '12.2(50)SY2' ) flag++;
if ( version == '12.4(15)T13' ) flag++;
if ( version == '12.4(15)T13b' ) flag++;
if ( version == '12.4(15)T14' ) flag++;
if ( version == '12.4(15)T15' ) flag++;
if ( version == '12.4(15)T16' ) flag++;
if ( version == '12.4(15)T17' ) flag++;
if ( version == '12.4(23a)' ) flag++;
if ( version == '12.4(23b)' ) flag++;
if ( version == '12.4(23b)M1' ) flag++;
if ( version == '12.4(23c)' ) flag++;
if ( version == '12.4(23d)' ) flag++;
if ( version == '12.4(23e)' ) flag++;
if ( version == '12.4(24)GC1' ) flag++;
if ( version == '12.4(24)GC3' ) flag++;
if ( version == '12.4(24)GC3a' ) flag++;
if ( version == '12.4(24)GC4' ) flag++;
if ( version == '12.4(24)MD' ) flag++;
if ( version == '12.4(24)MD1' ) flag++;
if ( version == '12.4(24)MD2' ) flag++;
if ( version == '12.4(24)MD3' ) flag++;
if ( version == '12.4(24)MD4' ) flag++;
if ( version == '12.4(24)MD5' ) flag++;
if ( version == '12.4(24)MD6' ) flag++;
if ( version == '12.4(24)MDA1' ) flag++;
if ( version == '12.4(24)MDA10' ) flag++;
if ( version == '12.4(24)MDA2' ) flag++;
if ( version == '12.4(24)MDA3' ) flag++;
if ( version == '12.4(24)MDA4' ) flag++;
if ( version == '12.4(24)MDA5' ) flag++;
if ( version == '12.4(24)MDA6' ) flag++;
if ( version == '12.4(24)MDA7' ) flag++;
if ( version == '12.4(24)MDA8' ) flag++;
if ( version == '12.4(24)MDA9' ) flag++;
if ( version == '12.4(24)MDB1' ) flag++;
if ( version == '12.4(24)MDB3' ) flag++;
if ( version == '12.4(24)MDB4' ) flag++;
if ( version == '12.4(24)MDB5' ) flag++;
if ( version == '12.4(24)MDB5a' ) flag++;
if ( version == '12.4(24)MDB6' ) flag++;
if ( version == '12.4(24)MDB7' ) flag++;
if ( version == '12.4(24)MDB8' ) flag++;
if ( version == '12.4(24)MDB9' ) flag++;
if ( version == '12.4(24)T1' ) flag++;
if ( version == '12.4(24)T2' ) flag++;
if ( version == '12.4(24)T3' ) flag++;
if ( version == '12.4(24)T31f' ) flag++;
if ( version == '12.4(24)T32f' ) flag++;
if ( version == '12.4(24)T33f' ) flag++;
if ( version == '12.4(24)T35c' ) flag++;
if ( version == '12.4(24)T3c' ) flag++;
if ( version == '12.4(24)T3e' ) flag++;
if ( version == '12.4(24)T3f' ) flag++;
if ( version == '12.4(24)T3g' ) flag++;
if ( version == '12.4(24)T4' ) flag++;
if ( version == '12.4(24)T4a' ) flag++;
if ( version == '12.4(24)T4b' ) flag++;
if ( version == '12.4(24)T4c' ) flag++;
if ( version == '12.4(24)T4d' ) flag++;
if ( version == '12.4(24)T4e' ) flag++;
if ( version == '12.4(24)T4f' ) flag++;
if ( version == '12.4(24)T5' ) flag++;
if ( version == '12.4(24)T6' ) flag++;
if ( version == '12.4(24)YE' ) flag++;
if ( version == '12.4(24)YE1' ) flag++;
if ( version == '12.4(24)YE2' ) flag++;
if ( version == '12.4(24)YE3' ) flag++;
if ( version == '12.4(24)YE3a' ) flag++;
if ( version == '12.4(24)YE3b' ) flag++;
if ( version == '12.4(24)YE3c' ) flag++;
if ( version == '12.4(24)YE3d' ) flag++;
if ( version == '12.4(24)YE4' ) flag++;
if ( version == '12.4(24)YE5' ) flag++;
if ( version == '12.4(24)YE6' ) flag++;
if ( version == '12.4(24)YE7' ) flag++;
if ( version == '12.4(24)YG1' ) flag++;
if ( version == '12.4(24)YG2' ) flag++;
if ( version == '12.4(24)YG3' ) flag++;
if ( version == '12.4(24)YG4' ) flag++;
if ( version == '12.4(25)' ) flag++;
if ( version == '12.4(25a)' ) flag++;
if ( version == '12.4(25b)' ) flag++;
if ( version == '12.4(25c)' ) flag++;
if ( version == '12.4(25d)' ) flag++;
if ( version == '12.4(25e)' ) flag++;
if ( version == '12.4(25f)' ) flag++;
if ( version == '15.0(1)M' ) flag++;
if ( version == '15.0(1)M1' ) flag++;
if ( version == '15.0(1)M2' ) flag++;
if ( version == '15.0(1)M3' ) flag++;
if ( version == '15.0(1)M4' ) flag++;
if ( version == '15.0(1)M5' ) flag++;
if ( version == '15.0(1)M6' ) flag++;
if ( version == '15.0(1)M6a' ) flag++;
if ( version == '15.0(1)M7' ) flag++;
if ( version == '15.0(1)XA' ) flag++;
if ( version == '15.0(1)XA1' ) flag++;
if ( version == '15.0(1)XA2' ) flag++;
if ( version == '15.0(1)XA3' ) flag++;
if ( version == '15.0(1)XA4' ) flag++;
if ( version == '15.0(1)XA5' ) flag++;
if ( version == '15.1(1)T' ) flag++;
if ( version == '15.1(1)T1' ) flag++;
if ( version == '15.1(1)T2' ) flag++;
if ( version == '15.1(1)T3' ) flag++;
if ( version == '15.1(1)T4' ) flag++;
if ( version == '15.1(1)T5' ) flag++;
if ( version == '15.1(1)XB' ) flag++;
if ( version == '15.1(1)XB1' ) flag++;
if ( version == '15.1(1)XB2' ) flag++;
if ( version == '15.1(1)XB3' ) flag++;
if ( version == '15.1(2)GC' ) flag++;
if ( version == '15.1(2)GC1' ) flag++;
if ( version == '15.1(2)T' ) flag++;
if ( version == '15.1(2)T0a' ) flag++;
if ( version == '15.1(2)T1' ) flag++;
if ( version == '15.1(2)T2' ) flag++;
if ( version == '15.1(2)T2a' ) flag++;
if ( version == '15.1(2)T3' ) flag++;
if ( version == '15.1(2)T4' ) flag++;
if ( version == '15.1(3)T' ) flag++;
if ( version == '15.1(3)T1' ) flag++;
if ( version == '15.1(3)T2' ) flag++;
if ( version == '15.1(4)M' ) flag++;
if ( version == '15.1(4)M0a' ) flag++;
if ( version == '15.1(4)M0b' ) flag++;
if ( version == '15.1(4)M1' ) flag++;
if ( version == '15.1(4)M2' ) flag++;
if ( version == '15.1(4)XB4' ) flag++;
if ( version == '15.1(4)XB5' ) flag++;
if ( version == '15.1(4)XB5a' ) flag++;
if ( version == '15.1(4)XB6' ) flag++;
if ( version == '15.2(1)GC' ) flag++;
if ( version == '15.2(1)GC1' ) flag++;
if ( version == '15.2(1)GC2' ) flag++;
if ( version == '15.2(1)T' ) flag++;
if ( version == '15.2(1)T1' ) flag++;
if ( version == '15.2(1)T2' ) flag++;
if ( version == '15.2(2)T' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"ip\s*nat\s*enable", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"ip\s*nat\s*inside", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"ip\s*nat\s*outside", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
