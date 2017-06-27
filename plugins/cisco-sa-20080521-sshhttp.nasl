#TRUSTED 8fd1d83aa0bed7ed4a9589e8c019274300f1594c02bbb2794d56539504137b91b379dd0dfc686c57eaca6bffe8b86f8e640879818871163227dca7d26b1bba20b45c2149d4f8f89254f9acf9dea11458e84b27dcbc0e6eaafadbf7bb2feb94b6263ffa693f18ab5ca3b3b4365b8777eff4e073a31d75ba3dd8591689103caa340ccd33e9cd3da45d238455ca8eaf84decd8cfeb6439355aef5e412272c9323e2d4ad4ae9bd76da5febdcea4d181f2c499ca2f89b28f5bc6127262510a2d8be1ba9b58eba1999f47a57af57026d0d7d68f3a3515085085f4c5a9d7f2161ed53d7ceca81986edbaaf6dd6cecacb16989de300e65b547a90b15ae90265adc3ca301d3cadd1c9410fb93495d54d773aadec42d48df4ab5ea3967b4e2ae31c4268ad5903564dc34a1a391a03c40583986e32cadf5ab627d8e957cf7391a372c8ed09dff52743c1c1ad8e0571e54d9f1db68994b8cc6a9905417da193a94053a5aba913f0c4140888d93bf92a91ed85edf7cc11663d60798faf9d37d20580a3b74fb0aaa0824de1296417767f0b45d2aa989f8af3402ffa997230161b57efddf32f328ba1500e690ff942d3b755db63054a29b44186850bf3b169a8c147283557e7ec6cb1457cb5046c3f47213f9f2c97a87e368b3dfa63ba61e95a3aba6d3ac818653f3d64a3381ce5092a831f2e467160dee33cfc94bbdeb673668c3b9b6fad77906
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a008099567f.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49015);
 script_version("1.15");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2008-1159");
 script_bugtraq_id(29314);
 script_osvdb_id(45674, 45675, 45676);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsh51293");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsk42419");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsk60020");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20080521-ssh");
 script_name(english:"Cisco IOS Secure Shell Denial of Service Vulnerabilities - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'The Secure Shell server (SSH) implementation in Cisco IOS contains
multiple vulnerabilities that allow unauthenticated users the ability
to generate a spurious memory access error or, in certain cases, reload
the device.
The IOS SSH server is an optional service that is disabled by default,
but its use is highly recommended as a security best practice for
management of Cisco IOS devices. SSH can be configured as part of the
AutoSecure feature in the initial configuration of IOS devices.
AutoSecure runs after initial configuration, or manually. SSH is enabled
any time RSA keys are generated such as when a http secure-server or
trust points for digital certificates are configured. Devices that are
not configured to accept SSH connections are not affected by these
vulnerabilities.'
 );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?04b73451");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a008099567f.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?7212db35");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20080521-ssh.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:C/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/05/21");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/05/21");
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
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

if (version == '12.4(11)XW6') flag++;
else if (version == '12.4(11)XW5') flag++;
else if (version == '12.4(11)XW4') flag++;
else if (version == '12.4(11)XW3') flag++;
else if (version == '12.4(11)XW2') flag++;
else if (version == '12.4(11)XW1') flag++;
else if (version == '12.4(11)XW') flag++;
else if (version == '12.4(11)XV1') flag++;
else if (version == '12.4(11)XV') flag++;
else if (version == '12.4(14)XK') flag++;
else if (version == '12.4(11)XJ4') flag++;
else if (version == '12.4(11)XJ3') flag++;
else if (version == '12.4(11)XJ2') flag++;
else if (version == '12.4(11)XJ') flag++;
else if (version == '12.4(15)XF') flag++;
else if (version == '12.4(6)XE3') flag++;
else if (version == '12.4(6)XE2') flag++;
else if (version == '12.4(6)XE1') flag++;
else if (version == '12.4(6)XE') flag++;
else if (version == '12.4(15)T1') flag++;
else if (version == '12.4(15)T') flag++;
else if (version == '12.4(11)T3') flag++;
else if (version == '12.4(11)T2') flag++;
else if (version == '12.4(11)T1') flag++;
else if (version == '12.4(11)T') flag++;
else if (version == '12.4(9)T5') flag++;
else if (version == '12.4(9)T4') flag++;
else if (version == '12.4(9)T3') flag++;
else if (version == '12.4(9)T2') flag++;
else if (version == '12.4(9)T1') flag++;
else if (version == '12.4(9)T') flag++;
else if (version == '12.4(15)SW') flag++;
else if (version == '12.4(11)SW3') flag++;
else if (version == '12.4(11)SW2') flag++;
else if (version == '12.4(11)SW1') flag++;
else if (version == '12.4(11)SW') flag++;
else if (version == '12.4(16)MR1') flag++;
else if (version == '12.4(16)MR') flag++;
else if (version == '12.4(12)MR2') flag++;
else if (version == '12.4(12)MR1') flag++;
else if (version == '12.4(12)MR') flag++;
else if (version == '12.4(11)MR') flag++;
else if (version == '12.4(13d)JA') flag++;
else if (version == '12.4(17)') flag++;
else if (version == '12.4(16a)') flag++;
else if (version == '12.4(16)') flag++;
else if (version == '12.4(13e)') flag++;
else if (version == '12.4(13d)') flag++;
else if (version == '12.4(13c)') flag++;
else if (version == '12.4(13b)') flag++;
else if (version == '12.4(13a)') flag++;
else if (version == '12.4(13)') flag++;
else if (version == '12.4(12c)') flag++;
else if (version == '12.4(12b)') flag++;
else if (version == '12.4(12a)') flag++;
else if (version == '12.4(12)') flag++;
else if (version == '12.4(10c)') flag++;
else if (version == '12.4(10b)') flag++;
else if (version == '12.4(10a)') flag++;
else if (version == '12.4(10)') flag++;
else if (version == '12.4(8d)') flag++;
else if (version == '12.4(8c)') flag++;
else if (version == '12.4(8b)') flag++;
else if (version == '12.4(8a)') flag++;
else if (version == '12.4(8)') flag++;
else if (version == '12.4(7h)') flag++;
else if (version == '12.4(7g)') flag++;
else if (version == '12.4(7f)') flag++;
else if (version == '12.4(7e)') flag++;
else if (version == '12.4(7d)') flag++;
else if (version == '12.4(7c)') flag++;
else if (version == '12.4(7b)') flag++;
else if (version == '12.4(7a)') flag++;
else if (version == '12.4(7)') flag++;


if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_ssh", "show ip ssh");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"SSH Enabled", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
