#TRUSTED 7496aa2a08390931044b952d9321c4f1c440760f52a4f93dbe2245fac9d54d5aaeb0f683d0443ea190af2f537b8f49f9616ad395f0031a57a868467eb7d4d5a29ef566824814cb506b81a448c498cca796677c9f1d5c7f08ea2535bda7e3e4d7f5a1e73f6772afce0f387702f2c656125d99dcd954afc86eec6bd9a51d3244d47fc0177ce9900bb75391bc115639a878f894b5c7aae574031913de85a83de572ac5216479192184c45b504c71d678d1d71adbdf1afc5a33455469a0ae626851398a8605a09cab2a3837fc3249881991ff5d062ec575c545dee7f59c5d1e8a1f2d412aa0ac65c9d4098cda7716bc8a33bd38fcbcec15117840fcf4719242397f2306660c6a90d7b7e591af76a157a8db88c244126483678eaa097681a5df29d15992629cbc5b82624e451f5b857da2f7c97a73d1bf1ab09e2991a11a748bc2045e0b0bc1d580f787b987ab3ca2c5cb177e24e376243a9925b051b5e04738d08f19f6ede1d61fc170c3a1aac8446e2b3478204c5d1d9cbc438412195252ed96a0437b0c763e6773bdfd9ecc065abe4a7fa81dc4b9d042c32c288f851efdaa6463d0bd324ef35bc85c058e4101749208c8460136c786f37954a4b6fe9b320a8249224a0b54b1fca0718e7b8d91adb335f51441a72cae484021e96b6252a5e81dd3833cf8af763196dff6559c7b6b9f3f68a19d1ff530282119df3801ed38c9a052d
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00806cd92f.shtml

include("compat.inc");

if (description)
{
 script_id(48993);
 script_version("1.15");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");

 script_cve_id("CVE-2006-3291");
 script_bugtraq_id(18704);
 script_osvdb_id(26878);
 script_xref(name:"CERT", value:"544484");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsd67403");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20060628-ap");

 script_name(english:"Access Point Web-browser Interface Vulnerability");
 script_summary(english:"Checks IOS version");

 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
"The Cisco web-browser interface for Cisco access points and Cisco 3200
Series Wireless Mobile Interface Card (WMIC), contains a vulnerability
that could, under certain circumstances, remove the default security
configuration from the managed access point and allow administrative
access without validation of administrative user credentials.

Cisco has made free software available to address this vulnerability
for affected customers. There are workarounds available to mitigate the
effects of this vulnerability.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83c42166");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00806cd92f.shtml
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4404fda");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20060628-ap.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(16);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/28");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/06/28");
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
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

if (version == '12.3(11)JX1') flag++;
else if (version == '12.3(11)JX') flag++;
else if (version == '12.3(8)JA1') flag++;
else if (version == '12.3(8)JA')  flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_http_server_status", "show ip http server status");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"HTTP server status: Enabled", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"HTTP secure server status: Enabled", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
