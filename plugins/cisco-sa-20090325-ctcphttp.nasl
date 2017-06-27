#TRUSTED 0e009a691324be5d8734102d8fdf2b530c852a34b9a27fc24d1a203f8e46629eb3e3ac8ac8cd5e5e1c956847a80d1f7be356d0e39d6363cd4212b258aef047453020cfed7e917b8e63c2e1099de5047ee7d872e211d72afeb9ff3188087e7d046942f4ce3c9a3eed5c60c339bb526656d3ac1e79112ccc047b00c98e61098bd3fed60dee8a0cbdefe8b1604486f8a30192c710f27b26243076c8d765925ff59442ade787c3c07db971a38cd7a129de1fff32355350b9768ff292ee6ac50393c45319af62c7027f2b0c456e2e73108d32587d8de7418c5c8106dfe5b4a8564d4636b786427b1fd0bb661e77b98dee57adf68f1cbd1b1c4796b2672edcbc09d684ed423e5a85fe7fecedda8aa4dafff4e6f3bf99ec99d4805379a5f36ac60bf5e953c78399b7c10f53594d19965d0a57d9f1c29efc78baef55b34f61c710746f716bb3fa967c12843630923bd824dd4ce500b80ceb9423f47fd98ba6cc184b7d3ee173af705dbeab6d04bf8d7202b5c38dfd2bfda91c544bf1f711fabe6121e8beb2632689adfbb5fa00f2df897c526eb06f866a652b88ca06f4aaebbfb759fd93ed89f132f578a05a4cd0848ea8ea79a56831c5f339fe3cfae02a4e6dae093e8b1a90897477dba9d96f6acf5f897b989fa5905ba04c68466ff11ea799451445fb63524c48d65b013eb913288b8101a0b50ccf1c6cf60afe127d9394f119817910
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080a96c2a.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49029);
 script_version("1.16");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2009-0635");
 script_bugtraq_id(34246);
 script_osvdb_id(53134);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsr16693");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsu21828");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20090325-ctcp");
 script_name(english:"Cisco IOS cTCP Denial of Service Vulnerability - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'A series of TCP packets may cause a denial of service (DoS) condition
on Cisco IOS devices that are configured as Easy VPN servers with the
Cisco Tunneling Control Protocol (cTCP) encapsulation feature. Cisco
has released free software updates that address this vulnerability. No
workarounds are available; however, the IPSec NAT traversal (NAT-T)
feature can be used as an alternative.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03cb73c5");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080a96c2a.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?148d2178");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20090325-ctcp.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(399);
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/25");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/03/25");
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
override = 0;
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '12.4(20)YA1') flag++;
else if (version == '12.4(20)YA') flag++;
else if (version == '12.4(15)XZ1') flag++;
else if (version == '12.4(15)XZ') flag++;
else if (version == '12.4(15)XY5') flag++;
else if (version == '12.4(15)XY4') flag++;
else if (version == '12.4(15)XY3') flag++;
else if (version == '12.4(15)XY2') flag++;
else if (version == '12.4(15)XY1') flag++;
else if (version == '12.4(15)XY') flag++;
else if (version == '12.4(11)XW9') flag++;
else if (version == '12.4(11)XW8') flag++;
else if (version == '12.4(11)XW7') flag++;
else if (version == '12.4(11)XW6') flag++;
else if (version == '12.4(11)XW5') flag++;
else if (version == '12.4(11)XW4') flag++;
else if (version == '12.4(11)XW3') flag++;
else if (version == '12.4(11)XW2') flag++;
else if (version == '12.4(11)XW10') flag++;
else if (version == '12.4(11)XW1') flag++;
else if (version == '12.4(11)XW') flag++;
else if (version == '12.4(11)XV1') flag++;
else if (version == '12.4(11)XV') flag++;
else if (version == '12.4(11)XJ4') flag++;
else if (version == '12.4(11)XJ3') flag++;
else if (version == '12.4(11)XJ2') flag++;
else if (version == '12.4(11)XJ') flag++;
else if (version == '12.4(15)XF') flag++;
else if (version == '12.4(6)XE3') flag++;
else if (version == '12.4(6)XE2') flag++;
else if (version == '12.4(6)XE1') flag++;
else if (version == '12.4(6)XE') flag++;
else if (version == '12.4(20)T1') flag++;
else if (version == '12.4(20)T') flag++;
else if (version == '12.4(15)T8') flag++;
else if (version == '12.4(15)T7') flag++;
else if (version == '12.4(15)T6') flag++;
else if (version == '12.4(15)T5') flag++;
else if (version == '12.4(15)T4') flag++;
else if (version == '12.4(15)T3') flag++;
else if (version == '12.4(15)T2') flag++;
else if (version == '12.4(15)T1') flag++;
else if (version == '12.4(15)T') flag++;
else if (version == '12.4(11)T4') flag++;
else if (version == '12.4(11)T3') flag++;
else if (version == '12.4(11)T2') flag++;
else if (version == '12.4(11)T1') flag++;
else if (version == '12.4(11)T') flag++;
else if (version == '12.4(9)T7') flag++;
else if (version == '12.4(9)T6') flag++;
else if (version == '12.4(9)T5') flag++;
else if (version == '12.4(9)T4') flag++;
else if (version == '12.4(9)T3') flag++;
else if (version == '12.4(9)T2') flag++;
else if (version == '12.4(9)T1') flag++;
else if (version == '12.4(9)T') flag++;
else if (version == '12.4(19)MR') flag++;
else if (version == '12.4(16)MR2') flag++;
else if (version == '12.4(16)MR1') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_crypto_ctcp", "show crypto ctcp");
    if (check_cisco_result(buf))
    {
      flag = 1;
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}



if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
