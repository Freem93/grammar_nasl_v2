#TRUSTED 78f18cb7a741e78a1e705a3150e1320e2abf4183b3c86032434b604baf2f1b478df21341c36275f10021aaaf54b3ba87784be51328820cb436208cf5fb233470e4dc3f86e7ca6ca1c8eff3bdf36fa6cd2511050d8f889044bebe6156b353496fb0f030b50447f70d23ddcb9dff1e602ec8511c69f61fa82fd8223e82fc12e10d76c7b1e35f84d8c9084354c33020e42f68cb53099b309526c4077d7fa4901573f8e5df798bb11546fe0641343f94c6b2b0df74a9bee845c640d551f2b2efc24838d7b34dce0eba6d408623d6b702cd25c46bbf51d1fced4650059d0f53311c727ebf23b0ac8dbc2b0941336e8518af93ebf09aa22685e68cefaea615fd53c0dc27a394fe7930464098efdfe590f1f91568f7bb105a30a33e03663d7e2259247b74f5a0f3c96ede51ba04e22ac21e3540f96a361c815f1ac18b85eb53deec8c4ac6a67c578887ee2529d872d8f04b163f17e573d2fa2d8252ae85a25b092c5ad235a26fadd4fbd9001b5b908346960bf6453e3e9d328ec35580311fce6f0722f4952d8df063d0223b1353d5e60525a6f724c5ee401b5e81b4f2d9fdc407d3e0eb2f82ee6513a577f1e489ae8f3fd7a4bf027c766838ca0d93532efb1155c4635c87a3b523e4a0c15c366a050cbac50b4e6265de76124da35052e4753de434971c164fedf1100fa062a577cb8b2cb40a74b835d8637a32a5ae15ecabd719dfb94e
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130327-ike.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(65886);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/03");

  script_cve_id("CVE-2013-1144");
  script_bugtraq_id(58742);
  script_osvdb_id(91758);
  script_xref(name:"CISCO-BUG-ID", value:"CSCth81055");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130327-ike");

  script_name(english:"Cisco IOS Software Internet Key Exchange Vulnerability (cisco-sa-20130327-ike)");
  script_summary(english:"Checks the IOS version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Cisco IOS Software Internet Key Exchange (IKE) feature contains a
denial of service (DoS) vulnerability. Cisco has released free
software updates that address this vulnerability. Workarounds that
mitigate this vulnerability are not available."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130327-ike
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d6f41905"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130327-ike."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if ( version == '15.1(2)GC2' ) flag++;
if ( version == '15.1(2)T' ) flag++;
if ( version == '15.1(2)T0a' ) flag++;
if ( version == '15.1(2)T1' ) flag++;
if ( version == '15.1(2)T2' ) flag++;
if ( version == '15.1(2)T2a' ) flag++;
if ( version == '15.1(2)T3' ) flag++;
if ( version == '15.1(2)T4' ) flag++;
if ( version == '15.1(2)T5' ) flag++;
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_udp", "show udp");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"17\s[^\r\n]*\s(500|4500|848|4848)", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_subsys", "show subsys");
    if (check_cisco_result(buf))
    {
      if (!preg(pattern:"ikev2\s+Library", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}



if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
