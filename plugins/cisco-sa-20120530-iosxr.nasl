#TRUSTED 0c843e8487c71aaa5c09c0fe424643d8a6642d835f5a3a2e4313a227fb6601cd7aab4a196f87fc4cac6935d22a869e4bca788a7dc99ae13a893a65e5fad89c2d6847635452bd9f674d729cd6d6f741d1aa6c33db0ca0d978889821ca9a130cfe1b582cfdc4c135c2a39361a8b3d5598298604e9f45808a849702e32a4f661ea0e527fbc9f328473a5039d507deef5a081c79aeeb20036de45e017a154ecc8cf27bb2ad8b5a12570f335d1ad259c67562d08ad92f3059fa2f5bc1256ff9cb399b97ce9c69f511b786bc906300591fe6368e92e8722406e432629d6d38ef609ad624bd0b83029dadcecbf17a92c4ade7fa58aba78a575931faf1901ebaf90bb9370c4edb73659f1b1fa5aa1efc5dbbcd551d4dea81069558282f10f914ba925a78628e179b530207a828fa54babf4b133925d132f6e32cbe26db0120c7a432e007cbf4e7b1dc402f2624aefa548d76f3d28ed544661ed8d57a2e490de200b9f0680ce533d94578e85bd4e1d1b5c28722b369a821a6f3b9dae50fd9f305fcf3dda4ada1a682796221eddfa430575c0664651d4116366c43ebd25577f5f67363637e1dab132722f165964f2703533b4dfea10d44d53cede0e7ddb077a84f9553c0f21c4062d36e2cde660c99f0e77a07bfcfdef4f8c195f1d9c89d3287c21d56f67b86117429d37819c73a6da4f00e50c242e3691daa786155c4aceeb7e85807f8a3
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20131023-iosxr.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(71435);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2013/12/14");

  script_cve_id("CVE-2012-2488");
  script_bugtraq_id(53728);
  script_osvdb_id(82457);
  script_xref(name:"CISCO-BUG-ID", value:"CSCty94537");
  script_xref(name:"CISCO-BUG-ID", value:"CSCua63591");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtz62593");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120530-iosxr");

  script_name(english:"Cisco IOS XR Software Route Processor Denial of Service Vulnerability (cisco-sa-20120530-iosxr)");
  script_summary(english:"Checks the IOS XR version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(
    attribute:"description", 
    value:
"Cisco IOS XR Software contains a vulnerability when handling crafted
packets that may result in a denial of service condition.  The
vulnerability only exists on Cisco 9000 Series Aggregation Services
Routers (ASR) Route Switch Processor (RSP-4G and RSP-8G), Route Switch
Processor 440 (RSP440), and Cisco Carrier Routing System (CRS)
Performance Route Processor (PRP).  The vulnerability is a result of
improper handling of crafted packets and could cause the route
processor, which processes the packets, to be unable to transmit packets
to the fabric."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120530-iosxr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14359465");
  script_set_attribute(
    attribute:"solution", 
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20120530-iosxr."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/23");
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
temp_flag = 0;
report = "";
override = 0;

cbi = "CSCua63591";

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
if ( version == '4.0.0' ) temp_flag++;
if ( version == '4.0.1' ) temp_flag++;
if ( version == '4.0.3' ) temp_flag++;
if ( version == '4.0.11' ) temp_flag++;
if ( version == '4.1.0' ) temp_flag++;
if ( version == '4.1.1' ) temp_flag++;
if ( version == '4.1.2' ) temp_flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_inventory", "show inventory");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"Route Switch Processor", string:buf)) { temp_flag = 1; }
    } else if (cisco_needs_enable(buf)) { temp_flag = 1; override = 1; }
  }
}
if (temp_flag)
{
  report +=
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed release : ' + version + '\n';
  flag++;
}

cbi = "CSCtz62593";
temp_flag = 0;
if ( version == '4.0.3' ) temp_flag++;
if ( version == '4.0.4' ) temp_flag++;
if ( version == '4.1.0' ) temp_flag++;
if ( version == '4.1.1' ) temp_flag++;
if ( version == '4.1.2' ) temp_flag++;
if ( version == '4.2.0' ) temp_flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_inventory", "show inventory");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"Performance Route Processor", string:buf)) { temp_flag = 1; }
    } else if (cisco_needs_enable(buf)) { temp_flag = 1; override = 1; }
  }
}
if (temp_flag)
{
  report +=
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed release : ' + version + '\n';
  flag++;
}

if (flag)
{
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);

}
else audit(AUDIT_HOST_NOT, "affected");
