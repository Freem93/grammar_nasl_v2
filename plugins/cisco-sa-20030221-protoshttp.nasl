#TRUSTED 479971759b0681fef54296df8176be46dca8af453ba669ff2260d26a6b59f03024289bd9d00b323f37f5ed6a1dd384bc3e44b2c41c701dab38801db14f2f0b4af992ab37a3b5493074525dc129667ac4fceac079efb242df82fef8242f44cda044ebaef95d82ed35ddce3162260e177097a08f76daf579ea2658feb1a9d05422c0c84fe667b4f413823275e529fe99acac7d210c901d93ee3ae90ad5919b9528995c97b73d5a0b4d2e4592542f814c9959e5c479e22afd0cca629d3fade628c438e5de6c5379ac72af8acdcdbac228c64551e03edeaf1e3be7cc2f7592347cb9c5c31217998eaed90c0c4a83b7f1e6a6fcc86c561b4096fd95aa9bed70bb0e53712377ac10647639e572c4d0997fbf3885db312ca0777e95bff776e6e212f9f376265517d302ab2439f5f9ef5e6827488000b23f5c92f446da34eb98cf96e3ae79c37d92c60f43d29a476f48eb3d3791faf1df1649bd47b3119163a8bc7a5f96731a913c7748b1cae437f665558be5e1c927316ec3b53d44d764ee6f80f79ba388557fb12157db1ed0269cac2d6408af30c5d3d977e0d5bfcde76262c207da80e0741af515bdf4a1585092ee3bb253466fdfe538de21008dd7d05469197dbdd38f0fbc26f3296e689a49d83afb4b7b4199b1f23495bcaada7d8495b6aa1a9c902201d7bf64e325a37d8efb0eb945cd5a28f4f4a817d4fac11681200e41e252d2
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a008014a251.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48969);
 script_version("1.13");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2003-1109");
 script_bugtraq_id(6904);
 script_osvdb_id(15412);
 script_xref(name:"CERT-CC", value:"528719");
 script_xref(name:"CERT-CC", value:"CA-2003-06");
 script_name(english:"Multiple Product Vulnerabilities Found by PROTOS SIP Test Suite - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
 script_set_attribute(attribute:"description", value:
' Multiple Cisco products contain vulnerabilities in the processing of
Session Initiation Protocol (SIP) INVITE messages. These
vulnerabilities were identified by the University of Oulu Secure
Programming Group (OUSPG) "PROTOS" Test Suite for SIP and can be
repeatedly exploited to produce a denial of service.
');
 script_set_attribute(attribute:"see_also", value:"https://www.ee.oulu.fi/research/ouspg/PROTOS_Test-Suite_c07-sip");
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20030221-protos
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?d6cc6d97");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a008014a251.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?089e2d67");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20030221-protos.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/02/21");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/02/21");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdx47789");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdz26317");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdz29003");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdz29033");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdz29041");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdz39284");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdz41124");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20030221-protos");
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

# Affected: 12.2 T
if (check_release(version: version,
                  patched: make_list("12.2(11)T3", "12.2(13)T1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_processes", "show processes");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"SIP", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

