#TRUSTED 792c746e076501c5aec827632f788f4d29e32a7c4b7dd798b007fa4a8d37ab24c6e346ef02164a170bde4f70fc67cc2da94a773b67ccfa45ae388f6f92cc4c950bb6038b8b3d660190ef9431c5124711bf0e42b50e963d6accd5cea88efa5ab8f824d10caa31b523037470312038f6930d1ad07d25c9687239acbd75162ffaff5c17bdd35f6706d8a72df44276483bbf31534256142d35b265fd7ff4ec71952948b9819257b3b62d5f529203a9afe13511511f662034e54e449443d77296e691d12c43415a307f69fa13c1773d6efb0e932ce36b00e2fcb0a181a3781ef0081fa2a550eee711911ec7a683efc7f3f584316d9a77551bdf7352f1f52a18df246575b357dd2af3d97427b1e50a1a52aebb3ed323d60bbfea7a424295026e5ca5accf9ef8e4b2e8760d60fa8a8233f2cbe9546b1fdb09af1bd204ba4ff3af204755f63fa9dc2b0e8739ca1645dce2bf172c75e3a203e8665b6041d5f70f176ff54c3e977f521a4d95e4f8b2e5c88e1e650b6fa096dc32a3ff4058995db2d2f23d3a5c4e88126fbb4ab47e34c64e73beb14fe75024651cd8a12fd266704af55393025da89e7f7b9c660587bd71c489bcb5c24dacb96a928b6be39e4376d978ab5ee23766e03f64db840668ac042eefe1c4206fd709eb4155455594b18f639faaac9575b95f1b7799b7af91c524f781ead340637ed16e58f74999959e4b39b4538a3f
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
  script_id(71436);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2013/12/14");

  script_cve_id("CVE-2012-4617");
  script_bugtraq_id(55694);
  script_osvdb_id(85814);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtt35379");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120926-bgp");

  script_name(english:"Cisco IOS XR Software Malformed Border Gateway Protocol Attribute Vulnerability (cisco-sa-20120926-bgp)");
  script_summary(english:"Checks the IOS XR version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(
    attribute:"description", 
    value:
"Cisco IOS XR Software contains a vulnerability in the Border Gateway
Protocol (BGP) routing protocol feature.  The vulnerability can be
triggered when the router receives a malformed attribute from a peer on
an existing BGP session.  Successful exploitation of this vulnerability
can cause all BGP sessions to reset.  Repeated exploitation may result
in an inability to route packets to BGP neighbors during reconvergence
times.  Cisco has released free software updates that address this
vulnerability.  There are no workarounds for this vulnerability."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120926-bgp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cfb7f0ef");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/04");
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

cbi = "CSCtt35379";

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
if ( version == '4.1.0' ) flag++;
if ( version == '4.1.1' ) flag++;
if ( version == '4.1.2' ) flag++;
if ( version == '4.2.0' ) flag++;
if ( version == '4.2.1' ) flag++;
if ( version == '4.2.2' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE,pattern:"router bgp", string:buf)) { temp_flag = 1; }
      if (preg(multiline:TRUE,pattern:"address-family (ipv4|ipv6) mvpn", string:buf)) { temp_flag = 1; }
      if (preg(multiline:TRUE,pattern:"neighbor", string:buf)) { temp_flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }

    if (temp_flag)
    {
      buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_bgp_neighbors", "show ip bgp neighbors");
      if (check_cisco_result(buf))
      {
        if (preg(multiline:TRUE,pattern:"neighbor", string:buf)) { flag = 1; }
      } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
    }
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
