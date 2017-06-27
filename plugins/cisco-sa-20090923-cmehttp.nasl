#TRUSTED 11d7e1dccdf23d79dc73362e264a133ba8f523c33b2ff73a3f85345ec430ec9b26e8846585a301c12f9d45d05b2ac2ed3cd15e34b2a94ce5f5d8c06a1dcacefc3adccee94178de107211a2c1cf35350b9c623f3b3a55af4ffc957f60bd303df1c2b0c318eb499b820ab3cd06b9e30d9e26a94177c8bd047e12e93265e157bb516ea1a3f6e10a6465280500c1a87dfca6f3e26b0e7f3bb853aa0ad96760346e038e67a11a127d036373946fecff79b823965d406f5fa7f6b41c204157950ce8a578e25c87e008c8ab398c10f3e0bb0054c958b75dcc94ad30780f69d4218514d8d64ba174ea309ad88e4b03b0664ee3d691f9f9af5732e4cbe4207a7c679e1bd22b4c3984ec40a46aea8c120cb8de9f744d3536fac594e700caa0ab664e2a28ac387fe7832009964509bc602ac2cb54eef220907ea1082e39e06ec75f23e2a7b4b36b41d37b6734a865ee4bc5df1319cce6732dae4e7e95b57f70c22db470e9d28801a3e5f708ea6e401f777e19fb517462278e181bea66cec90e59207c0ac28e27bb86d9dc929cad5f6c382ee957efe12d8bc6dd9ef42a52a4f921d11515faade2e95afffbcfc783c671ef746824381f83e2a617ed763d32da030598640c9895614b4075781ce049535cd5e0439d0ee0e2b7f98650accda8a3451c91392eaf322dbb4449ce3ba5f665e174a463df3e8e9802927e7880fecbed4d800dc42255c2
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080af8116.shtml

include("compat.inc");

if (description)
{
 script_id(49041);
 script_version("1.18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");

 script_cve_id("CVE-2009-2865");
 script_bugtraq_id(36498);
 script_osvdb_id(58335);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsq58779");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20090923-cme");

 script_name(english:"Cisco Unified Communications Manager Express Vulnerability - Cisco Systems");
 script_summary(english:"Checks IOS version");

 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
"Cisco IOS devices that are configured for Cisco Unified
Communications Manager Express (CME) and the Extension Mobility feature
are affected by a buffer overflow vulnerability. Successful
exploitation of this vulnerability may result in the execution of
arbitrary code or a denial of service (DoS) condition on an affected
device.

Cisco has released free software updates that address this
vulnerability.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?617ab31d");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080af8116.shtml
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c9935f5d");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20090923-cme.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/23");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/09/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
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

if (version == '12.4(20)YA') flag++;
else if (version == '12.4(15)XZ') flag++;
else if (version == '12.4(15)XY3') flag++;
else if (version == '12.4(15)XY2') flag++;
else if (version == '12.4(15)XY1') flag++;
else if (version == '12.4(15)XY') flag++;
else if (version == '12.4(11)XW7') flag++;
else if (version == '12.4(11)XW6') flag++;
else if (version == '12.4(11)XW5') flag++;
else if (version == '12.4(11)XW3') flag++;
else if (version == '12.4(11)XW2') flag++;
else if (version == '12.4(11)XW1') flag++;
else if (version == '12.4(11)XW') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"ephone ", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"logout-profile ", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
