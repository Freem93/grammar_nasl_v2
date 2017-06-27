#TRUSTED 67223f4573b4a46f3a6954c10e5ad88e59571ed2110b82156b9149acf8df069b34e14280214d7f4ba46a691a7c18eec1c73f1853e6453ca0c59680d0b03bab5f0bc2124459d43d4ca907733e7677edb6b9ba5b18f8b21e23d345a4f71f5822f52dc812a16bd1514629a6c633d97d4497327086be3a64545deb480abcae0e938921ab057d1b6e52ff49dded21d64c73c77a9f6d09c0cd08855a70771ca8bd83fea0f6daf0ba950019a853ce4847226cb92b7798b58fdc6329b87709e1a160e02514da71a54fafe1ec8f8cad76ec457f620ff5ecf80f119539fef7abde061958bee8f42709cb90f45bbcebcc017dda6f8a63d069e2a9936caae98569dc276f3a5524671b0717a196136a39d9e742bbde02c58090bbf4e5962422942e758076620ea62bfa3d7a4058dbd9168307b7bf3c85098cd59d56f2411ec6bd64881b35b08a69f06b534066eaff74b2ec59454d64c1144e78a1bbed5a959cee66d10eafa0ca2c6b3d52e4386f6c5169a374fef8a78ab9cd21d6f98eef0b14a3baeaa8f2d08f66eccb34113e05465be9f347bf6dec6e917c6528edbeea8e4ec248578dd60b5bdea49993ad3de7eb652c7632b35676d5a714f2b27eaf9be4e0b505368380f4d1208facc1e0da32655f745cca03692343313d00b7680587ce862dc1c44aa094988bb9697e991db265378358c4f5effd91fde8ba3e617cbd00831ac498c5ba3c0f
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080899647.shtml

include("compat.inc");

if (description)
{
  script_id(71432);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/12/19");

  script_cve_id("CVE-2007-4285");
  script_osvdb_id(36665, 36666);
  script_xref(name:"CISCO-BUG-ID", value:"CSCsi74127");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20070808-IOS-IPv6-leak");

  script_name(english:"Information Leakage Using IPv6 Routing Header in Cisco IOS XR (cisco-sa-20070808-IOS-IPv6-leak)");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Cisco IOS XR contains a vulnerability when processing specially crafted
IPv6 packets with a Type 0 Routing Header present. Exploitation of
this vulnerability leads to information leakage on affected IOS and
IOS XR devices, and can also result in a crash of the affected IOS
device. Successful exploitation on an affected device running Cisco
IOS XR will not result in a crash of the device itself, but may result
in a crash of the IPv6 subsystem.

Cisco has made free software available to address this vulnerability
for affected customers. There are workarounds available to mitigate
the effects of the vulnerability.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20070808-IOS-IPv6-leak
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b2a79cc3");
  # http://www.cisco.com/en/US/products/products_security_advisory09186a0080899647.shtml
  script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?d1931780");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20070808-IOS-IPv6-leak.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is (C) 2013-2014 Tenable Network Security, Inc.");
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


if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + version + '\n';
}
cbi = "CSCsi74127";
fixed_ver = "";

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
if (cisco_gen_ver_compare(a:version, b:"3.3.0") >= 0)
{
   if (version =~ '^3\\.3[^0-9]')
   {
     flag++;
     fixed_ver = "upgrade to 3.4.3.1 or later";
   }
   if ((version =~ '^3\\.4[^0-9]') && cisco_gen_ver_compare(a:version, b:"3.4.3.1") == -1)
   {
     flag++;
     fixed_ver = "3.4.3.1";
   }
   if ((version =~ '^3\\.5[^0-9]') && (version != "3.5.2.5") && cisco_gen_ver_compare(a:version, b:"3.5.2.6") == -1)
   {
     flag++;
     fixed_ver = "3.5.2.6";
   }
   if ((version =~ '^3\\.6[^0-9]') && (version != "3.6.0.10") && cisco_gen_ver_compare(a:version, b:"3.6.0.12") == -1)
   {
     flag++;
     fixed_ver = "3.6.0.12";
   }
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_interface", "show ipv6 interface");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"IPv6 is enabled", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report =
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + version +
    '\n  Fixed release     : ' + fixed_ver + '\n';

  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);

}
else audit(AUDIT_HOST_NOT, "affected");
