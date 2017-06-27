#TRUSTED 291e2451df0a3dd349fa606d950d2768660458a92639637a14379bccaf98dd20e728553456bfe1e96ec0e1f448a9d605d486f0ea585fb4f469ee5051683c42e9e583dc389b7823e265fa802a2a92ba9875b625f543fae2ce41a1fd1b814f0410740a3e80471f4006b93eb7c3f45e2ddfc6e0bb901312dba8916ceb151622a071402003a9d06c86dd38468ff22dfb760b99b2d2da0f7d62266a0801c920bece33d5d1ea6f5d5887b04ff30326bbb7146e23469784ff8603a4df95f5f452f887d1e594f97d1a236d026013e6162159ddedffa18dec8e83ea2fcb47024270fdfa4be42ed54417f0ed1479e27223d69edfbf6f23763a7a51e69b0493e8544121423e757650006be47ef24e688f55bf3829576242f5618dc7c3f05a7e1a98eca3a5e6b13cacf741da9fb3f8dbd62f430d1be708076313cd8e744778f80eb8d98387992e81820ffa8134c67eafd98ac9a324b26624c8179add5e21b83bb3fcd6e3377612fd396ccad11ef3d1093396c0017f84b8990e82b751487ac7d463da1c67c41125c34b0b0dc49981e3ccf7818a23ac12eb47d6d283167fb70189b538c48a6de78b061f4e7f4d666cf447c9e021a38ed4b1a5b9549a390aa201014f3fe7f89ae5640429299712e78b9a7376996de1f0a92d848d5e5f23f5972af8e4322197d36c13ed53001dc2e43419c79ad3b340929231f4205cade10aa405f3ea712547e99f
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080a01545.shtml

include("compat.inc");

if (description)
{
 script_id(49018);
 script_version("1.18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");

 script_cve_id("CVE-2008-3812");
 script_bugtraq_id(31354);
 script_osvdb_id(48734);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsh12480");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20080924-iosfw");

 script_name(english:"Cisco IOS Software Firewall Application Inspection Control Vulnerability");
 script_summary(english:"Checks IOS version");

 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
"Cisco IOS software configured for IOS firewall Application Inspection
Control (AIC) with a HTTP configured, application-specific policy are
vulnerable to a denial of service when processing a specific, malformed
HTTP transit packet.  Successful exploitation of the vulnerability may
result in a reload of the affected device.

Cisco has released free software updates that address this
vulnerability.

A mitigation for this vulnerability is available. See the 'Workarounds'
section for details.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b20ad075");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080a01545.shtml
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2e005ae");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20080924-iosfw.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/09/24");
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

if (version == '12.4(11)XW') flag++;
else if (version == '12.4(11)XV1') flag++;
else if (version == '12.4(11)XV') flag++;
else if (version == '12.4(14)XK') flag++;
else if (version == '12.4(11)XJ4') flag++;
else if (version == '12.4(11)XJ3') flag++;
else if (version == '12.4(11)XJ2') flag++;
else if (version == '12.4(11)XJ') flag++;
else if (version == '12.4(6)XE3') flag++;
else if (version == '12.4(6)XE2') flag++;
else if (version == '12.4(6)XE1') flag++;
else if (version == '12.4(6)XE') flag++;
else if (version == '12.4(11)T3') flag++;
else if (version == '12.4(11)T2') flag++;
else if (version == '12.4(11)T1') flag++;
else if (version == '12.4(11)T') flag++;
else if (version == '12.4(9)T6') flag++;
else if (version == '12.4(9)T5') flag++;
else if (version == '12.4(9)T4') flag++;
else if (version == '12.4(9)T3') flag++;
else if (version == '12.4(9)T2') flag++;
else if (version == '12.4(9)T1') flag++;
else if (version == '12.4(9)T') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_policy-map_type_inspect_zone-pair", "show policy-map type inspect zone-pair");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"Policy: http layer7-policymap", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
