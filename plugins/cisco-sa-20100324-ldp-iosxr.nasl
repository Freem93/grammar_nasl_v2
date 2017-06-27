#TRUSTED ad820c63558d5e53eaa09413f44e2f929bf4af7d9afd8bdd4025a264405043bd6e3151be85fdcb998515a6ad9e79437e81a4a8baee860f7134c43d2839aea0649795f37a5a56b80732c87a964f4f55f9e32587a373e1bd1528e0e97ffd084fd00fe28a16d17a3f7788e4a8053667f188c1ce9668a91d41d5dfc3b3e219fd29db34b0a101cb413621ecff820811955b5aa354cba14c061cec53c7159326df58cd48ab3283731db79d892361d1308eeb3dce3d84f4249143294279ffb20949911d3f382d761bec36da3b81f8777e0055d894d929ef88bd924d211863c103793e815d55cc9848255bf95b7b7d96a09be22143d05b65e4a36d8db243aa0a1104a2eb959ed93a1f9314f1d6ea38c850da6ada3c3d55ce7c23255579d97801b060aa068346f5a1c034994996f71d05c3bb67aa5cd64a98652328992c6ca2073cc8c2a6f846ee6f3d96c75fff9dca274b64c60143c9e0317a6915e31f3c84cef7c05292fde7956e73887b5bd207207aa7c262a681942ad61888cf9bcae9d6a9d4810ed14c87d95160ccdfb8178ca9fbf8345428eafadc950ebcce8caf9ae65ef916101e130c93cb788b1b184e4c60f2e2f8023329d1e65ebded3c73eb6f81afe951818eaa6d369cc82c8c2ba2f3d15a13b1ed0b65f8559539f89e1942ae6315b0352a81ff598dfd17305133f31a7ba4da2de7c47821c70321d763c2df61e1da70b76838
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20100324-ldp.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(71434);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2013/12/14");

  script_cve_id("CVE-2010-0576");
  script_osvdb_id(63188);
  script_bugtraq_id(38938);
  script_xref(name:"CISCO-BUG-ID", value:"CSCsj25893");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20100324-ldp");

  script_name(english:"Cisco IOS XR Software Multiprotocol Label Switching Packet Vulnerability (cisco-sa-20100324-ldp)");
  script_summary(english:"Checks the IOS XR version");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A device running Cisco IOS XR Software is vulnerable to a remote denial
of service (DoS) condition if it is configured for Multiprotocol Label
Switching (MPLS) and has support for Label Distribution Protocol (LDP). 
A crafted LDP UDP packet can cause an affected device running Cisco IOS
XR Software to restart the mpls_ldp process.  A system is vulnerable if
configured with either LDP or Tag Distribution Protocol (TDP).  Cisco
has released free software updates that address this vulnerability. 
Workarounds that mitigate this vulnerability are available."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20100324-ldp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?21b419a1");
  script_set_attribute(
    attribute:"solution", 
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20100324-ldp."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
report = "";
override = 0;

fixed_ver = "";
cbi = "CSCsj25893";

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
if (
     (cisco_gen_ver_compare(a:"3.5.0", b:version) >= 0) &&
     (cisco_gen_ver_compare(a:"3.5.2", b:version) < 0)
   ) flag ++;
fixed_ver = "3.5.2.6";

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_mpls", "show running-config mpls");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"mpls ldp", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    # Cisco IOS XR
    buf = cisco_command_kb_item("Host/Cisco/Config/show_udp_brief", "show udp brief");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:":646\s", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report =
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed Release : ' + version +
    '\n    Fixed Release     : ' + fixed_ver + '\n';

  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);

}
else audit(AUDIT_HOST_NOT, "affected");
