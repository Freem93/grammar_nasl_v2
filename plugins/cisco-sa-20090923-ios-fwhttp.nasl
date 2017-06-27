#TRUSTED 7d6726ca8e5f72282d704d45c4b5fb297b9b2ebb8b542cac4b4fcf9f34a378550a5ac13d1bd9ca0c2ac1cfc8e6c94ae0bf2f277e7e898b941e8a4776af1120b09f894432497a8ffba03e36b92b61ba5c6eefe4ced92195ba504dbdc60c9fbff50ee11e55e5730aca878418d1effa91634e17e23f5354a3e571f47dbfc068ff4d8aa02962104a03f84ffb6ea3667cdc484edcdb6d4568e052a839459ca7cd54eed116c1edaf31c440a42f5b668f80db1cbe7afdbad7b68e474d0cef2f4013c80a7ab573882f1614ee43f794fda3d35f11e1e374f7f1c2a0bd4381f873bbbd53f6cb976ec960e56ca6e055c62d9594fc2eb1101e9255b859092a368724137ba6e6148a1edfcea8bd61696fe18fe63e4dc0af5dcf69490928732944a56ead2caa46c3010bb28a7c6f608a95e8bee216a82e4b15511cf9d9a3f04e65b483a78b75a8e1548b399f65b6b7d515ecca71736673543ab2b912a1a80a6444db9787783469c228f158b2fe545a229ea63a8845efc5c702c98a31e1c9fc26b2c162739ad88f7ff81d8c2f875346fed83696d69388ce716f87dd6f9a3ea6b9e2d9c3e204a377cefc5e057611116d2762b400c147aa1a0bdf857adde7df0c7ab132972870283d2d77fb1bd2231998cb6ec2c6936295ecc90cd0762428c599b9e79752a990c46a840fae569e9848d2789a483420a24130dc4d7463f8efd61d5b2bdb87372571b9
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080af8130.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49043);
 script_version("1.15");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2009-2867");
 script_bugtraq_id(36492);
 script_osvdb_id(58341);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsr18691");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20090923-ios-fw");
 script_name(english:"Cisco IOS Software Zone-Based Policy Firewall Vulnerability - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Cisco IOS devices that are configured with Cisco IOS Zone-Based
Policy Firewall Session Initiation Protocol (SIP) inspection are
vulnerable to denial of service (DoS) attacks when processing a
specific SIP transit packet. Exploitation of the vulnerability could
result in a reload of the affected device.
Cisco has released free software updates that address this
vulnerability.
Workarounds that mitigate this vulnerability are available.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2e84522");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080af8130.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?77b0b7bc");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20090923-ios-fw.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/23");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/09/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2014 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '12.4(22)YB1') flag++;
else if (version == '12.4(22)YB') flag++;
else if (version == '12.4(20)YA3') flag++;
else if (version == '12.4(20)YA2') flag++;
else if (version == '12.4(20)YA1') flag++;
else if (version == '12.4(20)YA') flag++;
else if (version == '12.4(15)XZ2') flag++;
else if (version == '12.4(15)XZ1') flag++;
else if (version == '12.4(15)XZ') flag++;
else if (version == '12.4(22)T') flag++;
else if (version == '12.4(20)T1') flag++;
else if (version == '12.4(20)T') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_policy-map_type_inspect_zone-pair", "show policy-map type inspect zone-pair");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"Match: ", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
