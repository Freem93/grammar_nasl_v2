#TRUSTED a4f7ea6d969768992bae50e86057e80c5f25069111cb1bc29b2d83ee70a4c743cde9548dce25be63bea71f39be0bf5e6128da732da719d0a59f14b6553443cf6a32710fdb6c3daee4704a45dd1d939d79c6d63bfff2735339424a967c859827b05266873485b2ff78b2e44134d924948a87a723ca3d260ae39c37bce4f9d5b58b4dec98cea4ea8eccb1ae26346ae9f1e40448dd60065b19e5df07802282338999678a3519182cb0c4cf035a797ead41862b53d4b78364c49ee595cebc83db215dd35c3b88897a857915509301443eda900f0535fba32b2788ae92caedb493d669ee75f1bbdea2897c899f5e622ac3e9150547c01500a71abb82c9cb43d277a7db24ddec7fa463f0f7a05fde25b4a23e27a367c8d0753704f5f288be862f6d8340c72eac7f31d28ab31986b9df0ec87889624d0b5ad63e1c352e8fd1fdebc3f1fcb88cf444724e27a4f9bffb201b2c5e049a6054fa53320f75bfeff64b9a5f786c08864d9596e79037b624d6bf9256d41212c8ea71e4f895f68ec7cb6dcbdf893490f71623238c2f3171d1a40ee9b1ae70336d2a3bdc65031b93ce0f93177932718ce810835a23e41925535bb5dae60426bdf7acc1f63cc2a9b07ca04dd7bab2159159928ac31e1b154c311ef3f9fb908cea8d0e3d60265fa241fa42d18741a0acb266c81f71fc3a959899c67adce1ea6bfa7a3cfb552a114a50952f6fe96d76c
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080a0146c.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49026);
 script_version("1.15");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2008-3798");
 script_bugtraq_id(31365);
 script_osvdb_id(48712);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsj85065");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20080924-ssl");
 script_name(english:"Vulnerability in Cisco IOS While Processing SSL Packet - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'A Cisco IOS device may crash while processing an SSL packet. This can
happen during the termination of an SSL-based session. The offending
packet is not malformed and is normally received as part of the packet
exchange.
Cisco has released free software updates that address this
vulnerability. Aside from disabling affected services, there are no
available workarounds to mitigate an exploit of this vulnerability.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?688f60b8");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080a0146c.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?e17b5a90");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20080924-ssl.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

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
override = 0;#

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '12.4(16)MR2') flag++;
else if (version == '12.4(16)MR1') flag++;
else if (version == '12.4(16)MR') flag++;
else if (version == '12.4(17)') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"ip http secure-server", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"webvpn enable", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"url https[^\r\n]+:443", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
