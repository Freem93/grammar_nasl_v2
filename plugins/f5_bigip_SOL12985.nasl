#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution SOL12985.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(78129);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/10/31 13:45:40 $");

  script_cve_id("CVE-2011-1910");
  script_bugtraq_id(48007);
  script_osvdb_id(72540);

  script_name(english:"F5 Networks BIG-IP : BIND vulnerability (SOL12985)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Off-by-one error in named in ISC BIND 9.x before 9.7.3-P1, 9.8.x
before 9.8.0-P2, 9.4-ESV before 9.4-ESV-R4-P1, and 9.6-ESV before
9.6-ESV-R4-P1 allows remote DNS servers to cause a denial of service
(assertion failure and daemon exit) via a negative response containing
large RRSIG RRsets."
  );
  # http://support.f5.com/kb/en-us/solutions/public/12000/900/sol12985.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?641a6d6f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution SOL12985."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/10");
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

sol = "SOL12985";
vmatrix = make_array();

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("10.1.0-10.2.2");
vmatrix["APM"]["unaffected"] = make_list("10.2.2HF1","10.2.3-10.2.4","11");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("9.0.0-9.4.8","10.0.0-10.1.0","10.2.0-10.2.2");
vmatrix["ASM"]["unaffected"] = make_list("10.2.2HF1","10.2.3-10.2.4","11");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("9.0.0-9.4.8","10.0.0-10.1.0","10.2.0-10.2.2");
vmatrix["GTM"]["unaffected"] = make_list("10.2.2HF1","10.2.3-10.2.4","11");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("9.0.0-9.4.8","10.0.0-10.1.0","10.2.0-10.2.2");
vmatrix["LC"]["unaffected"] = make_list("10.2.2HF1","10.2.3-10.2.4","11");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("9.0.0-9.4.8","10.0.0-10.1.0","10.2.0-10.2.2");
vmatrix["LTM"]["unaffected"] = make_list("10.2.2HF1","10.2.3-10.2.4","11");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("9.0.0-9.4.8","10.0.0-10.1.0","10.2.0-10.2.2");
vmatrix["PSM"]["unaffected"] = make_list("10.2.2HF1","10.2.3-10.2.4","11");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("9.0.0-9.4.8","10.0.0-10.1.0","10.2.0-10.2.2");
vmatrix["WAM"]["unaffected"] = make_list("10.2.2HF1","10.2.3-10.2.4","11");

# WOM
vmatrix["WOM"] = make_array();
vmatrix["WOM"]["affected"  ] = make_list("10.0.0-10.1.0","10.2.0-10.2.2");
vmatrix["WOM"]["unaffected"] = make_list("10.2.2HF1","10.2.3-10.2.4","11");


if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  if (report_verbosity > 0) security_warning(port:0, extra:bigip_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = bigip_get_tested_modules();
  audit_extra = "For BIG-IP module(s) " + tested + ",";
  if (tested) audit(AUDIT_INST_VER_NOT_VULN, audit_extra, version);
  else audit(AUDIT_HOST_NOT, "running any of the affected modules");
}
