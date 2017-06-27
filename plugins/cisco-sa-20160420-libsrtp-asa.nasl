#TRUSTED 8ff0ed8c79a1e10a18f27b82fb75d1fedf21f39b35029c9d74a8a2e20caa11a35462360bc1738354f8b6453128fa950cd4eefc4c3cdb20a34c89d58c2cab62a7168c2be2e737d83d4871cd0806f6f84d4eca0606f94137d8870ea896ed6da7686e3b5c284a7f75f233e31d8c4925fd3a5adcd54b91e15bd3957de5dc25b54d2aa758243a0aaac8384916c263b43d99ea79b393adbb0191f24c8f16d5444a9405c6c02fb588bb7a920fe1b8f02880664997c00c97205c98504bce806bb9b8b6d658d5fedfea03bf8f3eadf353d717b3e6013d34fc49306dd6261f57806ac3a5778c78b9fcce20532daecc9c75baa9c7cc406aff7fcec350b39e0e2a9ccb14549a4c8bfec6a458a700b02cf781060ece92726f60043ab292d6422fabce81b747d25797fc581064e26019c4ceea9753213c9d2b91126fa50cf740dc82bc9ac52bea49cd43980bbfc0e345f191246c5b0dea1f790521bbdd941c350d9540041252f6dc26825d7e69cd81dc26218f08d26886d286278f48cf0975361de183beb97da9ab6ef8451dc0f352017da963ba892c61bc7b1e408194516badf82029710c28e9d5e689cb71c070729215dac76b88676c977374a7b379c8db5f85c00ff695a5b2de39583c39d7935a2fb7f88cca15ec081731a8ee6a2de5e1a83b4d660a54daa5560b99c06ad687a7fc4c5de951289b3430626383c249faeffbab619848caf86c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91759);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/06/22");

  script_cve_id("CVE-2015-6360");
  script_osvdb_id(131631);
  script_xref(name:"CISCO-BUG-ID", value:"CSCux00686");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160420-libsrtp");

  script_name(english:"Cisco ASA libsrtp DoS (CSCux00686)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Adaptive Security Appliance (ASA) is missing
vendor-supplied security patches, and it is configured to use the
Phone Proxy feature. It is, therefore, affected by an integer
underflow condition in the Secure Real-Time Transport Protocol (SRTP)
library due to improper validation of certain fields of SRTP packets.
An unauthenticated, remote attacker can exploit this, via specially
crafted SRTP packets, to cause packet decryption to fail, resulting in
a denial of service condition.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160420-libsrtp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1cb183fe");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch or workaround referenced in Cisco Security
Advisory cisco-sa-20160420-libsrtp.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/22");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');

ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

fixed_ver = NULL;
cbi = "CSCux00686";

# Check for vulnerable versions. Cisco ASA Phone Proxy feature was deprecated in 9.4.1
# 8.0 -> 8.3 do not have an upgrade in the same train. Upgrade these to 8.4(7.31)
if (ver =~ "^8\.[0-3][^0-9]")
{
  fixed_ver = "8.4(7.31)";
}
if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.31)"))
{
  fixed_ver = "8.4(7.31)";
}
else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(7)"))
{
  fixed_ver = "9.1(7)";
}
else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(4.6)"))
{
  fixed_ver = "9.2(4.6)";
}
else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(3.8)"))
{
  fixed_ver = "9.3(3.8)";
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

# Check if the keyword "phone-proxy" exists in the configuration. If it isn't
#   then the system is not vulnerable.
if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show-running-config-phone-proxy", "show running-config phone-proxy");
  if (check_cisco_result(buf))
  { 
    if (preg(string:buf, pattern:"^phone-proxy [^\s]+", multiline:TRUE)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because the phone proxy feature is not enabled");
}

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
