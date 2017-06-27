#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K14190.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(78142);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/03/16 14:01:51 $");

  script_cve_id("CVE-2013-0169");
  script_bugtraq_id(57778);
  script_osvdb_id(89848);

  script_name(english:"F5 Networks BIG-IP : TLS/DTLS 'Lucky 13' vulnerability (K14190)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability exists in the TLS and DTLS protocols that may allow an
attacker to recover plaintext from TLS/DTLS connections that use
CBC-mode encryption. (CVE-2013-0169)

Note: Stream ciphers, such as RC4, are not vulnerable to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/#/article/K14190"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K14190."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"F5 Networks Local Security Checks");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version", "Settings/ParanoidReport");

  exit(0);
}


include("f5_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
version = get_kb_item("Host/BIG-IP/version");
if ( ! version ) audit(AUDIT_OS_NOT, "F5 Networks BIG-IP");
if ( isnull(get_kb_item("Host/BIG-IP/hotfix")) ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/hotfix");
if ( ! get_kb_item("Host/BIG-IP/modules") ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/modules");

sol = "K14190";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("11.3.0-11.3.0HF1","12.1.0-12.1.0HF1","12.0.0-12.0.0HF3","11.6.1","11.6.0-11.6.0HF7","11.5.2-11.5.4HF1","11.5.1-11.5.1HF10","11.4.1-11.4.1HF10");
vmatrix["AFM"]["unaffected"] = make_list("12.0.0-12.1.1","11.4.0-11.6.1","11.3.0HF2","12.1.1","12.1.0HF2","12.0.0HF4","11.6.1HF1","11.6.0HF8","11.5.4HF2","11.5.1HF11","11.4.1HF11");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("12.1.0-12.1.0HF1","12.0.0-12.0.0HF3","11.6.1","11.6.0-11.6.0HF7","11.5.2-11.5.4HF1","11.5.1-11.5.1HF10","11.4.1-11.4.1HF10");
vmatrix["AM"]["unaffected"] = make_list("12.0.0-12.1.1","11.4.0-11.6.1","12.1.1","12.1.0HF2","12.0.0HF4","11.6.1HF1","11.6.0HF8","11.5.4HF2","11.5.1HF11","11.4.1HF11");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("11.3.0-11.3.0HF1","11.2.1-11.2.1HF3","11.2.0-11.2.0HF3","11.1.0-11.1.0HF5","11.0.0-11.0.0HF4","10.0.0-10.2.4HF4","12.1.0-12.1.0HF1","12.0.0-12.0.0HF3","11.6.1","11.6.0-11.6.0HF7","11.5.2-11.5.4HF1","11.5.1-11.5.1HF10","11.4.1-11.4.1HF10","11.2.1-11.2.1HF15","10.0.0-10.2.4");
vmatrix["APM"]["unaffected"] = make_list("12.0.0-12.1.1","11.4.0-11.6.1","11.3.0HF2","11.2.1HF4","11.2.0HF4","11.1.0HF6","11.0.0HF5","10.2.4HF6","12.1.1","12.1.0HF2","12.0.0HF4","11.6.1HF1","11.6.0HF8","11.5.4HF2","11.5.1HF11","11.4.1HF11","11.2.1HF16");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("11.3.0-11.3.0HF1","11.2.1-11.2.1HF3","11.2.0-11.2.0HF3","11.1.0-11.1.0HF5","11.0.0-11.0.0HF4","10.0.0-10.2.4HF4","12.1.0-12.1.0HF1","12.0.0-12.0.0HF3","11.6.1","11.6.0-11.6.0HF7","11.5.2-11.5.4HF1","11.5.1-11.5.1HF10","11.4.1-11.4.1HF10","11.2.1-11.2.1HF15","10.0.0-10.2.4");
vmatrix["ASM"]["unaffected"] = make_list("12.0.0-12.1.1","11.4.0-11.6.1","11.3.0HF2","11.2.1HF4","11.2.0HF4","11.1.0HF6","11.0.0HF5","10.2.4HF6","12.1.1","12.1.0HF2","12.0.0HF4","11.6.1HF1","11.6.0HF8","11.5.4HF2","11.5.1HF11","11.4.1HF11","11.2.1HF16");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("11.3.0-11.3.0HF1","11.2.1-11.2.1HF3","11.2.0-11.2.0HF3","11.1.0-11.1.0HF5","11.0.0-11.0.0HF4","12.1.0-12.1.0HF1","12.0.0-12.0.0HF3","11.6.1","11.6.0-11.6.0HF7","11.5.2-11.5.4HF1","11.5.1-11.5.1HF10","11.4.1-11.4.1HF10","11.2.1-11.2.1HF15");
vmatrix["AVR"]["unaffected"] = make_list("12.0.0-12.1.1","11.4.0-11.6.1","11.3.0HF2","11.2.1HF4","11.2.0HF4","11.1.0HF6","11.0.0HF5","12.1.1","12.1.0HF2","12.0.0HF4","11.6.1HF1","11.6.0HF8","11.5.4HF2","11.5.1HF11","11.4.1HF11","11.2.1HF16");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.3.0-11.3.0HF1","11.2.1-11.2.1HF3","11.2.0-11.2.0HF3","11.1.0-11.1.0HF5","11.0.0-11.0.0HF4","10.0.0-10.2.4HF4");
vmatrix["GTM"]["unaffected"] = make_list("11.4.0-11.6.1","11.3.0HF2","11.2.1HF4","11.2.0HF4","11.1.0HF6","11.0.0HF5","10.2.4HF6");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("11.3.0-11.3.0HF1","11.2.1-11.2.1HF3","11.2.0-11.2.0HF3","11.1.0-11.1.0HF5","11.0.0-11.0.0HF4","10.0.0-10.2.4HF4","12.1.0-12.1.0HF1","12.0.0-12.0.0HF3","11.6.1","11.6.0-11.6.0HF7","11.5.2-11.5.4HF1","11.5.1-11.5.1HF10","11.4.1-11.4.1HF10","11.2.1-11.2.1HF15","10.0.0-10.2.4");
vmatrix["LC"]["unaffected"] = make_list("12.0.0-12.1.1","11.4.0-11.6.1","11.3.0HF2","11.2.1HF4","11.2.0HF4","11.1.0HF6","11.0.0HF5","10.2.4HF6","12.1.1","12.1.0HF2","12.0.0HF4","11.6.1HF1","11.6.0HF8","11.5.4HF2","11.5.1HF11","11.4.1HF11","11.2.1HF16");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("11.3.0-11.3.0HF1","11.2.1-11.2.1HF3","11.2.0-11.2.0HF3","11.1.0-11.1.0HF5","11.0.0-11.0.0HF4","10.0.0-10.2.4HF4","12.1.0-12.1.0HF1","12.0.0-12.0.0HF3","11.6.1","11.6.0-11.6.0HF7","11.5.2-11.5.4HF1","11.5.1-11.5.1HF10","11.4.1-11.4.1HF10","11.2.1-11.2.1HF15","10.0.0-10.2.4");
vmatrix["LTM"]["unaffected"] = make_list("12.0.0-12.1.1","11.4.0-11.6.1","11.3.0HF2","11.2.1HF4","11.2.0HF4","11.1.0HF6","11.0.0HF5","10.2.4HF6","12.1.1","12.1.0HF2","12.0.0HF4","11.6.1HF1","11.6.0HF8","11.5.4HF2","11.5.1HF11","11.4.1HF11","11.2.1HF16");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("11.3.0-11.3.0HF1","12.1.0-12.1.0HF1","12.0.0-12.0.0HF3","11.6.1","11.6.0-11.6.0HF7","11.5.2-11.5.4HF1","11.5.1-11.5.1HF10","11.4.1-11.4.1HF10");
vmatrix["PEM"]["unaffected"] = make_list("12.0.0-12.1.1","11.4.0-11.6.1","11.3.0HF2","12.1.1","12.1.0HF2","12.0.0HF4","11.6.1HF1","11.6.0HF8","11.5.4HF2","11.5.1HF11","11.4.1HF11");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("11.3.0-11.3.0HF1","11.2.1-11.2.1HF3","11.2.0-11.2.0HF3","11.1.0-11.1.0HF5","11.0.0-11.0.0HF4","10.0.0-10.2.4HF4","11.3.0","11.2.1-11.2.1HF15","10.2.1-10.2.4");
vmatrix["PSM"]["unaffected"] = make_list("11.4.0-11.4.1","11.3.0HF2","11.2.1HF4","11.2.0HF4","11.1.0HF6","11.0.0HF5","10.2.4HF6","11.2.1HF16");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("11.3.0-11.3.0HF1","11.2.1-11.2.1HF3","11.2.0-11.2.0HF3","11.1.0-11.1.0HF5","11.0.0-11.0.0HF4","10.0.0-10.2.4HF4","11.3.0","11.2.1-11.2.1HF15","10.2.1-10.2.4");
vmatrix["WAM"]["unaffected"] = make_list("11.3.0HF2","11.2.1HF4","11.2.0HF4","11.1.0HF6","11.0.0HF5","10.2.4HF6","11.2.1HF16");

# WOM
vmatrix["WOM"] = make_array();
vmatrix["WOM"]["affected"  ] = make_list("11.3.0-11.3.0HF1","11.2.1-11.2.1HF3","11.2.0-11.2.0HF3","11.1.0-11.1.0HF5","11.0.0-11.0.0HF4","10.0.0-10.2.4HF4","11.3.0","11.2.1-11.2.1HF15","10.2.1-10.2.4");
vmatrix["WOM"]["unaffected"] = make_list("11.3.0HF2","11.2.1HF4","11.2.0HF4","11.1.0HF6","11.0.0HF5","10.2.4HF6","11.2.1HF16");


if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  if (report_verbosity > 0) security_note(port:0, extra:bigip_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = bigip_get_tested_modules();
  audit_extra = "For BIG-IP module(s) " + tested + ",";
  if (tested) audit(AUDIT_INST_VER_NOT_VULN, audit_extra, version);
  else audit(AUDIT_HOST_NOT, "running any of the affected modules");
}
