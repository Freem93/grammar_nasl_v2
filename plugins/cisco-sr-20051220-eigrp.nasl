#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(17788);
 script_version("$Revision: 1.5 $");
 script_cvs_date("$Date: 2017/05/10 19:18:33 $");

 script_cve_id("CVE-2002-2208");
 script_bugtraq_id(6443);
 script_osvdb_id(18055);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsc13698");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsc13724");
 script_xref(name:"CISCO-SR", value:"cisco-sr-20051220-eigrp");

 script_name(english:"Cisco EIGRP Multiple Vulnerabilities");
 script_summary(english:"Checks the version of Cisco IOS.");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
"On December 20 2005, Cisco released a security response for several
vulnerabilities in the EIGRP implementation in IOS. Exploitation of
these vulnerabilities could result in a denial of service via ARP
flooding. This plugin checks if the appropriate fix for the advisory
has been installed.");
 # http://www.cisco.com/en/US/products/csr/cisco-sr-20051220-eigrp.html
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?f7ccbbd6");
 # https://web.archive.org/web/20130103085342/http://www.cisco.com/en/US/docs/ios/12_0/np1/configuration/guide/1ceigrp.html
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?bac57393");
 # http://www.cisco.com/en/US/tech/tk365/technologies_security_notice09186a008011c5e1.html
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?7bcc8f04");
 # http://www.cisco.com/en/US/tech/tk648/tk361/technologies_white_paper09186a00801a1a55.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?1b8ae5b5");
 # http://www.cisco.com/en/US/docs/ios/12_2/security/configuration/guide/scfrpf.html
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?689673b1");
 # https://web.archive.org/web/20120508050313/http://www.cisco.com/en/US/docs/ios/12_3/12_3x/12_3xa/gt_802_1.html
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?c51e38ab");
 # https://web.archive.org/web/20121103030857/http://www.cisco.com/en/US/docs/ios/12_3t/ip_route/command/reference/ip2_i1gt.html
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?576186d2");
 script_set_attribute(attribute:"solution", value:"Upgrade to 12.0(6.3)PI, 12.0(6.3)T, 12.0(6.3)XE1, 12.0(7)T or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/12/19");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/12/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2012-2017 Tenable Network Security, Inc.");
 script_family(english:"CISCO");

 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}

include("cisco_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Affected: 12.0PI
if (check_release(version: version,
                  patched: make_list("12.0(6.3)PI") ))
{
  security_hole(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}
# Affected: 12.0T
if (check_release(version: version,
                  patched: make_list("12.0(6.3)T") ))
{
  security_hole(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}
# Affected: 12.0XE1
if (check_release(version: version,
                  patched: make_list("12.0(6.3)XE1") ))
{
  security_hole(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}
# Affected: 12.0T
if (check_release(version: version,
                  patched: make_list("12.0(7)T") ))
{
  security_hole(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n'); 
  exit(0);
}
exit(0, "The host is not affected.");
