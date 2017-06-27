#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution SOL15797.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(78877);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/10/31 13:45:41 $");

  script_cve_id("CVE-2012-4461");
  script_bugtraq_id(56414);

  script_name(english:"F5 Networks BIG-IP : Linux kernel vulnerability (SOL15797)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The KVM subsystem in the Linux kernel before 3.6.9, when running on
hosts that use qemu userspace without XSAVE, allows local users to
cause a denial of service (kernel OOPS) by using the KVM_SET_SREGS
ioctl to set the X86_CR4_OSXSAVE bit in the guest cr4 register, then
calling the KVM_RUN ioctl."
  );
  # http://support.f5.com/kb/en-us/solutions/public/15000/700/sol15797.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ee2d74a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution SOL15797."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

sol = "SOL15797";
vmatrix = make_array();

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("11.4.0-11.4.0HF7","11.3.0-11.3.0HF9");
vmatrix["AFM"]["unaffected"] = make_list("11.4.1-11.6.0","11.4.0HF8","11.3.0HF10");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("11.4.0-11.4.0HF7");
vmatrix["AM"]["unaffected"] = make_list("11.4.1-11.6.0","11.4.0HF8");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("11.4.0-11.4.0HF7","11.3.0-11.3.0HF9","11.2.1-11.2.1HF11","11.1.0-11.2.0");
vmatrix["APM"]["unaffected"] = make_list("11.4.1-11.6.0","11.4.0HF8","11.3.0HF10","11.2.1HF12","11.0.0","10.1.0-10.2.4");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("11.4.0-11.4.0HF7","11.3.0-11.3.0HF9","11.2.1-11.2.1HF11","11.1.0-11.2.0");
vmatrix["ASM"]["unaffected"] = make_list("11.4.1-11.6.0","11.4.0HF8","11.3.0HF10","11.2.1HF12","11.0.0","10.0.0-10.2.4");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("11.4.0-11.4.0HF7","11.3.0-11.3.0HF9","11.2.1-11.2.1HF11","11.1.0-11.2.0");
vmatrix["AVR"]["unaffected"] = make_list("11.4.1-11.6.0","11.4.0HF8","11.3.0HF10","11.2.1HF12","11.0.0");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.4.0-11.4.0HF7","11.3.0-11.3.0HF9","11.2.1-11.2.1HF11","11.1.0-11.2.0");
vmatrix["GTM"]["unaffected"] = make_list("11.4.1-11.6.0","11.4.0HF8","11.3.0HF10","11.2.1HF12","11.0.0","10.0.0-10.2.4");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("11.4.0-11.4.0HF7","11.3.0-11.3.0HF9","11.2.1-11.2.1HF11","11.1.0-11.2.0");
vmatrix["LC"]["unaffected"] = make_list("11.4.1-11.6.0","11.4.0HF8","11.3.0HF10","11.2.1HF12","11.0.0","10.0.0-10.2.4");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("11.4.0-11.4.0HF7","11.3.0-11.3.0HF9","11.2.1-11.2.1HF11","11.1.0-11.2.0");
vmatrix["LTM"]["unaffected"] = make_list("11.4.1-11.6.0","11.4.0HF8","11.3.0HF10","11.2.1HF12","11.0.0","10.0.0-10.2.4");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("11.4.0-11.4.0HF7","11.3.0-11.3.0HF9");
vmatrix["PEM"]["unaffected"] = make_list("11.4.1-11.6.0","11.4.0HF8","11.3.0HF10");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("11.4.0-11.4.0HF7","11.3.0-11.3.0HF9","11.2.1-11.2.1HF11","11.1.0-11.2.0");
vmatrix["PSM"]["unaffected"] = make_list("11.4.1","11.4.0HF8","11.3.0HF10","11.2.1HF12","11.0.0","10.0.0-10.2.4");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("11.3.0-11.3.0HF9","11.2.1-11.2.1HF11","11.1.0-11.2.0");
vmatrix["WAM"]["unaffected"] = make_list("11.3.0HF10","11.2.1HF12","11.0.0","10.0.0-10.2.4");

# WOM
vmatrix["WOM"] = make_array();
vmatrix["WOM"]["affected"  ] = make_list("11.3.0-11.3.0HF9","11.2.1-11.2.1HF11","11.1.0-11.2.0");
vmatrix["WOM"]["unaffected"] = make_list("11.3.0HF10","11.2.1HF12","11.0.0","10.0.0-10.2.4");


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
