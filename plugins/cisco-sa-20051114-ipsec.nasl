#TRUSTED 8d6aa75df3d07dda28ce68a98d575b9169d1699520ba1444baf1a0fd7bc35237acb78053ff87fb5562aa0233ec734b80b6110bcd824359537f6637d1c8c09aa2e9a05f94ce06986cada5381f09b1e2f4b68867835a4beee9e8bb7fcab88c1fe0ebf21676b0cf0b9663e0a02826e9163a028d360524dce7a3f0de7dde931da9a7f3a530269676aeb183b0a2a453caf099f7f374101652dc6415c5b6ae43e37ae32a0dcf2efa65aa6467b009d9880c4b22f3e93c6f4c7bb4329bca685cdca761398b0f33ffed8fccb2efc6f2dcca9fa5cb32383c3d81e01c8954c1bbeb6ca71db7bb0d1e2214330a661fe2ac9c209e0e55846e50351ec4a926438ed949a050394a912e7e4a0d4afbc989f9b7614a3d3ca97392515647adec5333aecff770311cc75e55852469f5a1f1e3208262f0e9b91ad115a2e2f6e791e7ce9f7e2df2fbf7f754d58ad74ba4c4ac71c041f1e2be70bec52c9cee93214b2bec6ef90005a94133e7a177dec38cae5f9e58f181b6765ca2dd9a9ebfd9b2b063e983f9783da2fc43bb57556c5e5f82a4eb4b91e4127070e69ef78b73c3ce9427d9634475b9af7662f3a4c395e4aa670492cc5062cc4ec93bd6169b6e3e92a1ef963dadcb793898e14143d0ff4823d3656dec5b340d401dacb2f1dc56009538b0105109bee253dad8aa94b59e7edc7aa5b5ec6b4d9ebda8a83f6c2c812983876935e069532ebb9668
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080572f55.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48990);
 script_version("1.14");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2005-3669");
 script_bugtraq_id(15401);
 script_osvdb_id(60990);
 script_xref(name:"CERT", value:"226364");
 script_name(english:"Multiple Vulnerabilities Found by PROTOS IPSec Test Suite - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Multiple Cisco products contain vulnerabilities in the processing of
IPSec IKE (Internet Key Exchange) messages. These vulnerabilities were
identified by the University of Oulu Secure Programming Group (OUSPG)
"PROTOS" Test Suite for IPSec and can be repeatedly exploited to
produce a denial of service.
Cisco has made free software available to address this vulnerability
for affected customers. Prior to deploying software, customers should
consult their maintenance provider or check the software for feature
set compatibility and known issues specific to their environment.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?49cf7a82");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080572f55.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?385edd10");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20051114-ipsec.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/11/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCed94829");
 script_xref(name:"CISCO-BUG-ID", value:"CSCei14171");
 script_xref(name:"CISCO-BUG-ID", value:"CSCei15053");
 script_xref(name:"CISCO-BUG-ID", value:"CSCei19275");
 script_xref(name:"CISCO-BUG-ID", value:"CSCei46258");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsb15296");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsc75655");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20051114-ipsec");
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

if (version == '12.4(2)XA2') flag++;
else if (version == '12.4(2)XA1') flag++;
else if (version == '12.4(2)XA') flag++;
else if (version == '12.4(2)T1') flag++;
else if (version == '12.4(2)T') flag++;
else if (version == '12.4(3a)') flag++;
else if (version == '12.4(3)') flag++;
else if (version == '12.4(1b)') flag++;
else if (version == '12.4(1a)') flag++;
else if (version == '12.4(1)') flag++;
else if (version == '12.3(8)ZA') flag++;
else if (version == '12.3(14)YU1') flag++;
else if (version == '12.3(14)YU') flag++;
else if (version == '12.3(14)YT1') flag++;
else if (version == '12.3(14)YT') flag++;
else if (version == '12.3(11)YS1') flag++;
else if (version == '12.3(11)YS') flag++;
else if (version == '12.3(14)YQ3') flag++;
else if (version == '12.3(14)YQ2') flag++;
else if (version == '12.3(14)YQ1') flag++;
else if (version == '12.3(14)YQ') flag++;
else if (version == '12.3(11)YK2') flag++;
else if (version == '12.3(11)YK1') flag++;
else if (version == '12.3(11)YK') flag++;
else if (version == '12.3(8)YI3') flag++;
else if (version == '12.3(8)YI2') flag++;
else if (version == '12.3(8)YI1') flag++;
else if (version == '12.3(8)YH') flag++;
else if (version == '12.3(8)YG3') flag++;
else if (version == '12.3(8)YG2') flag++;
else if (version == '12.3(8)YG1') flag++;
else if (version == '12.3(8)YG') flag++;
else if (version == '12.3(11)YF4') flag++;
else if (version == '12.3(11)YF3') flag++;
else if (version == '12.3(11)YF2') flag++;
else if (version == '12.3(11)YF1') flag++;
else if (version == '12.3(11)YF') flag++;
else if (version == '12.3(8)YD1') flag++;
else if (version == '12.3(8)YD') flag++;
else if (version == '12.3(8)YA1') flag++;
else if (version == '12.3(8)YA') flag++;
else if (version == '12.3(8)XX1') flag++;
else if (version == '12.3(8)XX') flag++;
else if (version == '12.3(8)XW3') flag++;
else if (version == '12.3(8)XW2') flag++;
else if (version == '12.3(8)XW1') flag++;
else if (version == '12.3(8)XW') flag++;
else if (version == '12.3(8)XU5') flag++;
else if (version == '12.3(8)XU4') flag++;
else if (version == '12.3(8)XU3') flag++;
else if (version == '12.3(8)XU2') flag++;
else if (version == '12.3(7)XS2') flag++;
else if (version == '12.3(7)XS1') flag++;
else if (version == '12.3(7)XS') flag++;
else if (version == '12.3(7)XR6') flag++;
else if (version == '12.3(7)XR5') flag++;
else if (version == '12.3(7)XR4') flag++;
else if (version == '12.3(7)XR3') flag++;
else if (version == '12.3(7)XR2') flag++;
else if (version == '12.3(7)XR') flag++;
else if (version == '12.3(4)XQ1') flag++;
else if (version == '12.3(4)XQ') flag++;
else if (version == '12.3(11)XL1') flag++;
else if (version == '12.3(11)XL') flag++;
else if (version == '12.3(4)XK4') flag++;
else if (version == '12.3(4)XK3') flag++;
else if (version == '12.3(4)XK2') flag++;
else if (version == '12.3(4)XK1') flag++;
else if (version == '12.3(4)XK') flag++;
else if (version == '12.3(7)XJ2') flag++;
else if (version == '12.3(7)XJ1') flag++;
else if (version == '12.3(7)XJ') flag++;
else if (version == '12.3(7)XI7') flag++;
else if (version == '12.3(7)XI6') flag++;
else if (version == '12.3(7)XI5') flag++;
else if (version == '12.3(7)XI4') flag++;
else if (version == '12.3(7)XI3') flag++;
else if (version == '12.3(7)XI2a') flag++;
else if (version == '12.3(7)XI2') flag++;
else if (version == '12.3(7)XI1c') flag++;
else if (version == '12.3(7)XI1b') flag++;
else if (version == '12.3(7)XI1') flag++;
else if (version == '12.3(4)XG5') flag++;
else if (version == '12.3(4)XG4') flag++;
else if (version == '12.3(4)XG3') flag++;
else if (version == '12.3(4)XG2') flag++;
else if (version == '12.3(4)XG1') flag++;
else if (version == '12.3(4)XG') flag++;
else if (version == '12.3(2)XF') flag++;
else if (version == '12.3(2)XE4') flag++;
else if (version == '12.3(2)XE3') flag++;
else if (version == '12.3(2)XE2') flag++;
else if (version == '12.3(2)XE1') flag++;
else if (version == '12.3(2)XE') flag++;
else if (version == '12.3(4)XD4') flag++;
else if (version == '12.3(4)XD3') flag++;
else if (version == '12.3(4)XD2') flag++;
else if (version == '12.3(4)XD1') flag++;
else if (version == '12.3(4)XD') flag++;
else if (version == '12.3(4)TPC11a') flag++;
else if (version == '12.3(14)T3') flag++;
else if (version == '12.3(14)T2') flag++;
else if (version == '12.3(14)T1') flag++;
else if (version == '12.3(14)T') flag++;
else if (version == '12.3(11)T8') flag++;
else if (version == '12.3(11)T7') flag++;
else if (version == '12.3(11)T6') flag++;
else if (version == '12.3(11)T5') flag++;
else if (version == '12.3(11)T4') flag++;
else if (version == '12.3(11)T3') flag++;
else if (version == '12.3(11)T2') flag++;
else if (version == '12.3(11)T') flag++;
else if (version == '12.3(8)T9') flag++;
else if (version == '12.3(8)T8') flag++;
else if (version == '12.3(8)T7') flag++;
else if (version == '12.3(8)T6') flag++;
else if (version == '12.3(8)T5') flag++;
else if (version == '12.3(8)T4') flag++;
else if (version == '12.3(8)T3') flag++;
else if (version == '12.3(8)T11') flag++;
else if (version == '12.3(8)T10') flag++;
else if (version == '12.3(8)T1') flag++;
else if (version == '12.3(8)T') flag++;
else if (version == '12.3(7)T9') flag++;
else if (version == '12.3(7)T8') flag++;
else if (version == '12.3(7)T7') flag++;
else if (version == '12.3(7)T6') flag++;
else if (version == '12.3(7)T4') flag++;
else if (version == '12.3(7)T3') flag++;
else if (version == '12.3(7)T2') flag++;
else if (version == '12.3(7)T12') flag++;
else if (version == '12.3(7)T11') flag++;
else if (version == '12.3(7)T10') flag++;
else if (version == '12.3(7)T1') flag++;
else if (version == '12.3(7)T') flag++;
else if (version == '12.3(4)T9') flag++;
else if (version == '12.3(4)T8') flag++;
else if (version == '12.3(4)T7') flag++;
else if (version == '12.3(4)T6') flag++;
else if (version == '12.3(4)T4') flag++;
else if (version == '12.3(4)T3') flag++;
else if (version == '12.3(4)T2') flag++;
else if (version == '12.3(4)T11') flag++;
else if (version == '12.3(4)T10') flag++;
else if (version == '12.3(4)T1') flag++;
else if (version == '12.3(4)T') flag++;
else if (version == '12.2(18)SXD6') flag++;
else if (version == '12.2(18)SXD5') flag++;
else if (version == '12.2(18)SXD4') flag++;
else if (version == '12.2(18)SXD3') flag++;
else if (version == '12.2(18)SXD2') flag++;
else if (version == '12.2(18)SXD1') flag++;
else if (version == '12.2(18)SXD') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_udp", "show udp");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"\s500\s", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"\s4500\s", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"\s848\s", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"\s4848\s", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

