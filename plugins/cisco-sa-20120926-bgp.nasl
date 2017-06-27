#TRUSTED 485e0f117d6374218b492bc429aa014499ebc017e5cfcc76de0696b7b83a170d6b5bd25c7d6f33ae72c7291a20b019060655454ca6cba92985c5df5ebe7790dbc9b804325ee4f3ae23d6ec9ee4cf77411e975d48006631f420c2ab525e0744100d53ee582160e2058076721a4c0274637957f553f52e8ec0a7e11e6bb824bc8d3275b1409eb1f23c6850fde6786fa3829e87a2eea35c0bf7d409eee344dfeecc574d59236997e3649445100a911484209baa83b81c53edf3da559f6b363ec529597e1921c932292cb1f47f27a7c1ec5698cb8f184a04fd8a006c0f966eb84c7094c0076afc2d19af4cd6e48f280303e64fcae1b73b0125e68dc91adb6ada10708d994abfe7b6430f3b60da6b3f7d3c32d9409a229fc7c684a7f089e1a092cc751fb66f6308bc2a76f10093ba4534bd4a3b4e2f9b7b4acd7ace3bda41913481481a6eb45db52d8a95f7bf97e6d71f00469a0cb75907eb58aa8d46332b010d2ac537e040b5ff145dce041ac534a699ea6f0885264c5e5ef57a1a6dac91271b91501d1d2dea900d664f73098d7c345111412fd0cb795fe535f5ec7f498cb1faa79f538026f8e82fc2b1065ec145f7df2ceb55aa954627ae220802b42b35efb66c5fe353320bfd5b4e8539bf57a924c0f7726603ceca57df6373152e6a94f9ab9d6710e542f406b1193dbdc6bb59ca3bf8f1b0c34e37a2f7ed6bf9ce976f0de40feb
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20120926-bgp.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(62370);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/03");

  script_cve_id("CVE-2012-4617");
  script_bugtraq_id(55694);
  script_osvdb_id(85814);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtt35379");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120926-bgp");

  script_name(english:"Cisco IOS Software Malformed Border Gateway Protocol Attribute Vulnerability (cisco-sa-20120926-bgp)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Cisco IOS Software contains a vulnerability in the Border Gateway
Protocol (BGP) routing protocol feature. The vulnerability can be
triggered when the router receives a malformed attribute from a peer
on an existing BGP session. Successful exploitation of this
vulnerability can cause all BGP sessions to reset. Repeated
exploitation may result in an inability to route packets to BGP
neighbors during reconvergence times. Cisco has released free software
updates that address this vulnerability. There are no workarounds for
this vulnerability."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120926-bgp
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cfb7f0ef"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20120926-bgp."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/04");
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
if ( version == '15.2(1)S' ) flag++;
if ( version == '15.2(1)S1' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_bgp_neighbors", "show ip bgp neighbors");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"neighbor", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}



if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
