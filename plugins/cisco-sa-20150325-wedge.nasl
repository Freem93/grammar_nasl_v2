#TRUSTED 977ea159dd29259b98faca910c738864b27d95134414158dd05957157ccf52792a5d42ec53476f14610c352735882975ac197854dd19a1adce0b23fc21c127f8e0a032bc77883168c38af6cd587491302c16f71162b7afd25f992486a15eb9cecb2e93addda1645f967837613d4517ff8072de340f30428a759b50997784bc4aae0071fd2081ecb2f7bf6a5b4ce61daa863de86d10529ab478312b728dcf86780d313877359d5d73940c86d06a1e7ea8cb59a51153871c5cd9f7aaa8b281831b3b002c93b1220f1221aebaf063177aef0f5767fc1de33b631f37e197d77d75ea970c194654b84e2a1dc4d122815bfe85f972990941c98cf9c8a7fa71f6ce72306572d63fa8259e775c1c906563f9694e1bc75a3ac913ca0d4a9c4c04aeeab3a840b10547b3e6c22a4d1d91de884ab9b7721463b1db90b78d1dc1780fbc9a1591e65a0a6f0b4dcb6141988aa5f1ac6cabd60cd07f8f2ec6b32c9453e3aad3d92931caa656b2cebf775adcde50e6395cca0db275e7e8ab444cae8dc0f01722ab51c854c2012c7ab43751f920b837f5ce9e18aad48f2deaf241b3a0ae9ce012ca7e053eb9b3d1ec412502d6eca36cdb9ad839beb82801e5a748c4a61369ccb786125fa988fa90a0b030a0557d56879eac1003a785fed4d2df501e79936e094cbb367063c920a015338d0af71928e20f6779e734095ec362ac54ab0ca69671e7c590
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82570);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/08/02");

  script_cve_id("CVE-2015-0638");
  script_bugtraq_id(73338);
  script_osvdb_id(119938);
  script_xref(name:"CISCO-BUG-ID", value:"CSCsi02145");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150325-wedge");

  script_name(english:"Cisco IOS Software VRF ICMP Queue Wedge DoS (cisco-sa-20150325-wedge)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description",value:
"The Cisco IOS software running on the remote device is affected by a
vulnerability in the Virtual Routing and Forwarding (VRF) interface
due to improperly processing crafted ICMPv4 messages, which leaves the
packet queue uncleared. A remote remote attacker can exploit this to
cause a 'queue wedge' on the interface, stopping any further packets
from being received and thus causing a denial of service condition.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-wedge
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3a5132b");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20150325-wedge. Note that Cisco has released free software
updates that address this vulnerability. Workarounds that mitigate
this issue are not available.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/03");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

model = get_kb_item("Host/Cisco/IOS/Model");
if (empty_or_null(model))
  model = "Unknown Cisco IOS device";

if (version == '12.2(33)IRD1') flag++;
if (version == '12.2(33)IRE3') flag++;
if (version == '12.2(44)SQ1') flag++;
if (version == '12.2(33)SXI4b') flag++;
if (version == '12.4(25e)JAM1') flag++;
if (version == '12.4(25e)JAP1m') flag++;
if (version == '12.4(25e)JAZ1') flag++;
if (version == '15.0(2)ED1') flag++;
if (version == '15.2(1)EX') flag++;
if (version == '15.2(2)GC') flag++;
if (version == '15.2(2)JA1') flag++;
if (version == '15.3(2)S2') flag++;
if (version == '15.3(3)JN') flag++;
if (version == '15.3(3)JNB') flag++;
if (version == '15.3(3)JAB1') flag++;
if (version == '15.3(3)JA1n') flag++;
if (version == '15.2(3)XA') flag++;
if (version == '15.2(3)T1') flag++;
if (version == '15.2(2)T1') flag++;
if (version == '15.2(2)T3') flag++;
if (version == '15.2(2)T2') flag++;
if (version == '15.2(2)JB1') flag++;
if (version == '15.2(2)JAX1') flag++;
if (version == '15.2(2)JB4') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_vrf", "show vrf");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"\s+\S+\s+\S+\s+ipv4\s+\S+", multiline:TRUE, string:buf))
        flag = 1;
    }
    else if (cisco_needs_enable(buf))
    {
      flag = 1;
      override = 1;
    }
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Model       : ' + model +
      '\n  IOS Version : ' + version +
      cisco_caveat(override) +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_DEVICE_NOT_VULN, model, version);
