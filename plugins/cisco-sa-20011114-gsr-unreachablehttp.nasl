#TRUSTED 3de4a37429c921b35314f4b638ee18d225080d044a4976b228ce5324596cab88804b1adb15d8defe4ce7e6c1aead895eae6f969dc9ec75eb6ab0c6ccd962af9ec886314b001ead826b2db5f7b2ced7eb6e0684ab576f489fb7b2be86c9de69a2a73bc72c41ff41cdbe8dcb0a0ffa62db68416f157ac1f2f34ef1b78f323b5e44426674985a4a9c09217c6b1617b59ea7ae18b84b20ce62c79292fc222bc055c71c9b93dc639b780eff3c83d0c74f8a1702ca59acc60026b8176c592b179a26fec804de46fd2990929066838171f4dfbd8daa32f37f5db943b10deef0b4e12c8e050438012f3169735365bf250cc1560196af69b5a88c8a24a8e73f8cd1f6123f5badae3b4b9bd99bba6780ba13205f359a7e395b396bf935f956f240d49c6eb2f868a784b4bf6076664e8ef578ee0e6a00178b926475c56e2e3893d044e21787d59e77a4e830d6ffda2c8f9ada7693c90c7dcc4b2ea330b2c4ae4235bd38d2e7240845c1fa523087df5ff9f4198661090caa58d3f71e231d8fcac2d45b4a6b131797543fce749a5f17bc23b9115180e983b6e157216d0fed2648caadeec5de23193927442a77ed065b9bc7e4c926a2b46c891ab4ded248022c7a2b28f772be0d9e025faf693f1ca085d27157e6b9e0ab0b3c06273ebaa368237dbf54c58d353a3313208a138955522c5359ed4a1c6f7c13852a8aa2522abed4f4a65b749b2fca
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080094250.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48960);
 script_version("1.11");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2001-0861");
 script_bugtraq_id(3534);
 script_osvdb_id(794);
 script_name(english:"ICMP Unreachable Vulnerability in Cisco 12000 Series Internet Router - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
 script_set_attribute(attribute:"description", value:
'The performance of Cisco 12000 series routers can be degraded when they
have to send a large number of ICMP unreachable packets. This situation
usually can occur during heavy network scanning. This vulnerability is
tracked by three different bug IDs: CSCdr46528 ( registered customers
only) , CSCdt66560 ( registered customers only) , and CSCds36541 (
registered customers only) . Each bug ID is assigned to a different
Engine the line card is based upon.
The rest of the Cisco routers and switches are not affected by this
vulnerability. It is specific for Cisco 12000 Series.
No other Cisco product is vulnerable.
The workaround is to either prevent the router from sending unreachable
Internet Control Message Protocol (ICMPs) at all or to rate limit them. ');
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20011114-gsr-unreachable
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e37ea3d2");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080094250.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?64a44880");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20011114-gsr-unreachable.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/11/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2001/11/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdr46528");
 script_xref(name:"CISCO-BUG-ID", value:"CSCds36541");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt66560");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20011114-gsr-unreachable");
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
report_extra = "";
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

# Vulnerability CSCdr46528
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(16)S1", "12.0(16.5)S", "12.0(17)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(15.6)ST3", "12.0(16)ST", "12.0(16.5)ST"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

# Vulnerability CSCds36541
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(13.6)S2", "12.0(14)S", "12.0(14.1)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(14.3)ST"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

# Vulnerability CSCdt66560
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(16)S1", "12.0(16.6)S", "12.0(17)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_diag", "show diag");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"L3\s+Engine:\s+0", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"L3\s+Engine:\s+1", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"L3\s+Engine:\s+2", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_warning(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
