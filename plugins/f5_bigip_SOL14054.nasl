#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K14054.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(78139);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/03/16 14:01:51 $");

  script_osvdb_id(85927);

  script_name(english:"F5 Networks BIG-IP : CRIME vulnerability via TLS 1.2 protocol (K14054)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The TLS protocol 1.2 and earlier, as used in Mozilla Firefox, Google
Chrome, and other products, can encrypt compressed data without
properly obfuscating the length of the unencrypted data. This allows
man-in-the-middle attackers to obtain plain text HTTP headers by
observing length differences during a series of guesses in which a
string in an HTTP request potentially matches an unknown string in an
HTTP header, also referred to as a CRIME attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/#/article/K14054"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K14054."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"F5 Networks Local Security Checks");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version");

  exit(0);
}


include("f5_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
version = get_kb_item("Host/BIG-IP/version");
if ( ! version ) audit(AUDIT_OS_NOT, "F5 Networks BIG-IP");
if ( isnull(get_kb_item("Host/BIG-IP/hotfix")) ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/hotfix");
if ( ! get_kb_item("Host/BIG-IP/modules") ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/modules");

sol = "K14054";
vmatrix = make_array();

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("10.1.0-10.2.4","11.0.0-11.2.1");
vmatrix["APM"]["unaffected"] = make_list("10.0.0-10.0.1","10.2.4HF6","11.1.0HF6","11.2.0HF4","11.2.1HF4","11.3.0-11.4.0");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("10.1.0-10.2.4","11.0.0-11.2.1");
vmatrix["ASM"]["unaffected"] = make_list("9.2.0-9.4.8","10.0.0-10.0.1","10.2.4HF6","11.1.0HF6","11.2.0HF4","11.2.1HF4","11.3.0-11.4.0");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("11.0.0-11.2.1");
vmatrix["AVR"]["unaffected"] = make_list("11.1.0HF6","11.2.0HF4","11.2.1HF4","11.3.0-11.4.0");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("10.1.0-10.2.4","11.0.0-11.2.1");
vmatrix["GTM"]["unaffected"] = make_list("9.2.2-9.4.8","10.0.0-10.0.1","10.2.4HF6","11.1.0HF6","11.2.0HF4","11.2.1HF4","11.3.0-11.4.0");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("10.1.0-10.2.4","11.0.0-11.2.1");
vmatrix["LC"]["unaffected"] = make_list("9.2.2-9.4.8","10.0.0-10.0.1","10.2.4HF6","11.1.0HF6","11.2.0HF4","11.2.1HF4","11.3.0-11.4.0");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("10.1.0-10.2.4","11.0.0-11.2.1");
vmatrix["LTM"]["unaffected"] = make_list("9.0.0-9.4.8","10.0.0-10.0.1","10.2.4HF6","11.1.0HF6","11.2.0HF4","11.2.1HF4","11.3.0-11.4.0");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("10.1.0-10.2.4","11.0.0-11.2.1");
vmatrix["PSM"]["unaffected"] = make_list("9.4.0-9.4.8","10.0.0-10.0.1","10.2.4HF6","11.1.0HF6","11.2.0HF4","11.2.1HF4","11.3.0-11.4.0");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("10.1.0-10.2.4","11.0.0-11.2.1");
vmatrix["WAM"]["unaffected"] = make_list("9.4.0-9.4.8","10.0.0-10.0.1","10.2.4HF6","11.1.0HF6","11.2.0HF4","11.2.1HF4","11.3.0");

# WOM
vmatrix["WOM"] = make_array();
vmatrix["WOM"]["affected"  ] = make_list("10.1.0-10.2.4","11.0.0-11.2.1");
vmatrix["WOM"]["unaffected"] = make_list("10.0.0-10.0.1","10.2.4HF6","11.1.0HF6","11.2.0HF4","11.2.1HF4","11.3.0");


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
