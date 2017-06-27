#TRUSTED 26127bf90bcbc591d2a924695db7529926d75e4e6d563fc6a6d3381ef89021ffb8ddee5e948eb2f74360ad546de7666ede602e6641deb297d916c7249e157a4f6fcb1890eea0328ad351c78d633ecf323838a240f01a0df5de246fb011c198b8a1bc47536b8ee0a066b6453fcc916b0b277fef896a9f27ba3d7e3b929f6bfd8da6dc04cfdc760f279e789d878e4a4639c9c5fb6638219bd005d4c87b505f9fcde0c33ff26c56e6d163a3bd0c6836432472c735684e20a48cae502ca1c94b3fb20067654235dbe05f552fd9c2b5684d6bb9ab08a4776905d55b080ff8700a1e0c9d466235bdf870561a1830cc2723181499cbc7c496457c0924c575e14632eb6dd72ccf5d1d81364e1e59ee67ae6af60b1ea8b96525b64750b4588ccdba61e1bdfbad10a1609a7f95830179cd1a94831d68042d6d87be476683723115bac4b4b1851b6bed60232df40f62a24208c686a210fcfa9becaceb28f2ff6542ce982dca4d99e95d3c49dde14fd027851b52c922767e8c773e641c6e73800c69e45b2e6d231293673c73ebbc3903b1fe18c696539ec131652c83aba5a988d74ddda1584796f116f5b22378b33ac560a44d41b32ebc2f5c7d9ea2a45da54875ec5c2316f822b397fdc5d2821cf0a7a1f46759e1eac00149270cc972f22aaf1bfc2f3bc4d6969b6c6db3754e6b5ba23848b939e394a9af456a7018a8295b2bc8599967041a
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20131106-sip.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(73269);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/10/03");

  script_cve_id("CVE-2014-2107");
  script_bugtraq_id(66468);
  script_osvdb_id(104967);
  script_xref(name:"CISCO-BUG-ID", value:"CSCug84789");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140326-RSP72010GE");

  script_name(english:"Cisco 7600 Series Route Switch Processor 720 with 10 Gigabit Ethernet Uplinks Denial of Service (cisco-sa-20140326-RSP72010GE)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability exists in Cisco 7600 Series Route Switch Processor
720 with 10 Gigabit Ethernet Uplinks that could allow a remote,
unauthenticated attacker to cause the route processor to reboot or
stop forwarding traffic, resulting in a denial of service condition.

This vulnerability affects models RSP720-3C-10GE and RSP720-3CXL-10GE
that have onboard Kailash FPGA versions prior to 2.6 and are running
an affected version of Cisco IOS Software.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140326-RSP72010GE
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bbdc7e10");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140326-RSP72010GE.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/31");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
cbi = "CSCug84789";

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");
if (ver == '12.2SRC') flag++;
if (ver == '12.2(33)SRC') flag++;
if (ver == '12.2(33)SRC1') flag++;
if (ver == '12.2(33)SRC2') flag++;
if (ver == '12.2(33)SRC3') flag++;
if (ver == '12.2(33)SRC4') flag++;
if (ver == '12.2(33)SRC5') flag++;
if (ver == '12.2(33)SRC6') flag++;
if (ver == '12.2SRD') flag++;
if (ver == '12.2(33)SRD') flag++;
if (ver == '12.2(33)SRD1') flag++;
if (ver == '12.2(33)SRD2') flag++;
if (ver == '12.2(33)SRD2a') flag++;
if (ver == '12.2(33)SRD3') flag++;
if (ver == '12.2(33)SRD4') flag++;
if (ver == '12.2(33)SRD4a') flag++;
if (ver == '12.2(33)SRD5') flag++;
if (ver == '12.2(33)SRD6') flag++;
if (ver == '12.2(33)SRD7') flag++;
if (ver == '12.2(33)SRD8') flag++;
if (ver == '12.2SRE') flag++;
if (ver == '12.2(33)SRE') flag++;
if (ver == '12.2(33)SRE0a') flag++;
if (ver == '12.2(33)SRE1') flag++;
if (ver == '12.2(33)SRE2') flag++;
if (ver == '12.2(33)SRE3') flag++;
if (ver == '12.2(33)SRE4') flag++;
if (ver == '12.2(33)SRE5') flag++;
if (ver == '12.2(33)SRE6') flag++;
if (ver == '12.2(33)SRE7') flag++;
if (ver == '12.2(33)SRE7a') flag++;
if (ver == '12.2(33)SRE8') flag++;
if (ver == '12.2(33)SRE9') flag++;
if (ver == '12.2(33)SRE9a') flag++;
if (ver == '12.2ZI') flag++;
if (ver == '12.2(33)ZI') flag++;
if (ver == '12.2ZZ') flag++;
if (ver == '12.2(33)ZZ') flag++;
if (ver == '15.0S') flag++;
if (ver == '15.0(1)S') flag++;
if (ver == '15.0(1)S1') flag++;
if (ver == '15.0(1)S2') flag++;
if (ver == '15.0(1)S3a') flag++;
if (ver == '15.0(1)S4') flag++;
if (ver == '15.0(1)S4a') flag++;
if (ver == '15.0(1)S5') flag++;
if (ver == '15.0(1)S6') flag++;
if (ver == '15.1S') flag++;
if (ver == '15.1(1)S') flag++;
if (ver == '15.1(1)S1') flag++;
if (ver == '15.1(1)S2') flag++;
if (ver == '15.1(2)S') flag++;
if (ver == '15.1(2)S1') flag++;
if (ver == '15.1(2)S2') flag++;
if (ver == '15.1(3)S') flag++;
if (ver == '15.1(3)S0a') flag++;
if (ver == '15.1(3)S1') flag++;
if (ver == '15.1(3)S2') flag++;
if (ver == '15.1(3)S3') flag++;
if (ver == '15.1(3)S4') flag++;
if (ver == '15.1(3)S6') flag++;
if (ver == '15.2S') flag++;
if (ver == '15.2(1)S') flag++;
if (ver == '15.2(1)S1') flag++;
if (ver == '15.2(1)S2') flag++;
if (ver == '15.2(2)S') flag++;
if (ver == '15.2(2)S1') flag++;
if (ver == '15.2(2)S2') flag++;
if (ver == '15.2(4)S') flag++;
if (ver == '15.2(4)S1') flag++;
if (ver == '15.2(4)S3a') flag++;
if (ver == '15.2(4)S4') flag++;
if (ver == '15.2(4)S4a') flag++;
if (ver == '15.3S') flag++;
if (ver == '15.3(1)S') flag++;
if (ver == '15.3(1)S2') flag++;
if (ver == '15.3(2)S') flag++;
if (ver == '15.3(2)S0a') flag++;
if (ver == '15.3(2)S1') flag++;
if (ver == '15.3(2)S2') flag++;
if (ver == '15.3(3)S') flag++;
if (ver == '15.3(3)S1') flag++;

if (get_kb_item("Host/local_checks_enabled") && flag)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_module", "show module");
  if (check_cisco_result(buf))
  {
    pattern = "(\d+)\s+\d+\s+Route Switch Processor 720.*?(RSP720-3CXL-10GE|RSP720-3C-10GE)";
    match = eregmatch(string:buf, pattern:pattern);
    if (!isnull(match))
    {
      temp_flag = 1;
      slot = match[1];
    }
  }
  else if (cisco_needs_enable(buf)) override = 1;

  if (temp_flag)
  {
    buf = cisco_command_kb_item(
      "Host/Cisco/Config/show_asic-version_slot_" + slot,
      "show asic-version slot " + slot);
    if (check_cisco_result(buf))
    {
      pattern = "KAILASH\s+\d+\s+\(((?:\d+\.)*\d+)\)";
      match = eregmatch(string:buf, pattern:pattern);
      if (!isnull(match) && ver_compare(ver:match[1], fix:"2.6", strict:FALSE) == -1) flag = 1;
    }
    else if (cisco_needs_enable(buf)) override = 1;
  }

  if (override) flag = 1;
}

if (flag)
{
  report =
    '\n  Cisco Bug ID      : ' + cbi +
    '\n  Installed release : ' + ver + '\n';
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
