#TRUSTED 2e6315b4f1d4eb6dd378be5e255689c9f2f3b88490c50158380476d31b3d965e0edffbe0fdde0145dece6090378e1d216addbce8bc69bcc57d58eaff2c42f272d382a50b031bbbf8354fff92a7d6865fcc226520e0cea63979dc88d631ee04ff02ffdf66f691527dd140cd659412d100d01881ce4f4c358d6be1e185433080a7a1df1ff4099ba778e6e5e778a10780802d4b34c280cfffd1b6260304280bf842a012fee11b33f19542f18d161b3c50da48aeeec3fadd0d25d6f4d3d99d4404bc7bf96506531e771afaf308ced3fffc0807aa5700b99f2d093d7d99c58b008f1be34fe49df17b9d6ea4b82e7ec0dd9a5f71c22a16eb03ac91bf5e8d62982ba2a1adbfaf3b8e820201579f89d4cdefaed9e3ad8f3a99f89ea3f66ba29707639726727fa9f415dc02363892eacdd7a3e3a86e1a99c66502a11c766723166c4b89d9b692bf3fa87e30bbc3b1b0782825ba601fb54deeebece7cb88abdbe10451174c590e0938ac1cfad6171bff1eba5c6284cf32757c811455185cb32a474d13c149a76f623254f8b2fe5717f3d6f119041259d1a3b4b1b016297fe4515f075f87c39aed35d23345c965633936f711e5274dc87ffbd77df235741024d1bb24fffcdd5499ea0390ad2238c05cbca8cc45e7226cd06c0c6deb3c31ff2307c13a1ed303493dfe2abe807d6abca796c0764aeca7009c8312516af0535241e42ba7061c78
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20131002-iosxr.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(71437);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2013/12/14");

  script_cve_id("CVE-2013-5503");
  script_bugtraq_id(62770);
  script_osvdb_id(98022);
  script_xref(name:"CISCO-BUG-ID", value:"CSCue69413");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20131002-iosxr");

  script_name(english:"Cisco IOS XR Software Memory Exhaustion Vulnerability (cisco-sa-20131002-iosxr)");
  script_summary(english:"Checks the IOSXR version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(
    attribute:"description", 
    value:
"Cisco IOS XR Software version 4.3.1 contains a vulnerability that could
result in complete packet memory exhaustion.  Successful exploitation
could render critical services on the affected device unable to allocate
packets resulting in a denial of service (DoS) condition.  Cisco has
released free software updates that address this vulnerability. 
Workarounds that mitigate this vulnerability are available."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20131002-iosxr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3edb503");
  script_set_attribute(
    attribute:"solution", 
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20131002-iosxr."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/02");
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

cbi = "CSCue69413";

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
if ( version == '4.3.1' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_udp_brief", "show udp brief");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:":(161|162|123|646|514)", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report =
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed release : ' + version + '\n';

  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);

}
else audit(AUDIT_HOST_NOT, "affected");
