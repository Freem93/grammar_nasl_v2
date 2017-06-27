#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution SOL14261.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(78145);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/10/31 13:45:41 $");

  script_cve_id("CVE-2013-0166");
  script_bugtraq_id(57755, 60268);

  script_name(english:"F5 Networks BIG-IP : OpenSSL OCSP vulnerability (SOL14261)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"OpenSSL before 0.9.8y, 1.0.0 before 1.0.0k, and 1.0.1 before 1.0.1d do
not properly perform signature verification for Online Certificate
Status Protocol (OCSP) responses, which allow remote attackers to
cause a denial-of-service (DoS) (NULL pointer dereference and
application crash) by way of an invalid key."
  );
  # http://support.f5.com/kb/en-us/solutions/public/14000/200/sol14261.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ea1e8b93"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution SOL14261."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/07");
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

sol = "SOL14261";
vmatrix = make_array();

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("11.3.0");
vmatrix["AFM"]["unaffected"] = make_list("11.4.0","11.3.0HF2");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("11.0.0-11.3.0","10.1.0-10.2.4");
vmatrix["APM"]["unaffected"] = make_list("11.4.0","11.3.0HF2","11.2.1HF4","11.2.0HF4","11.1.0HF6","11.0.0HF5","10.2.4HF6");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("11.0.0-11.3.0","10.0.0-10.2.4","9.2.0-9.4.8");
vmatrix["ASM"]["unaffected"] = make_list("11.4.0","11.3.0HF2","11.2.1HF4","11.2.0HF4","11.1.0HF6","11.0.0HF5","10.2.4HF6");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("11.0.0-11.3.0");
vmatrix["AVR"]["unaffected"] = make_list("11.4.0","11.3.0HF2","11.2.1HF4","11.2.0HF4","11.1.0HF6","11.0.0HF5");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("11.0.0-11.3.0","10.0.0-10.2.4","9.2.2-9.4.8");
vmatrix["LC"]["unaffected"] = make_list("11.4.0","11.3.0HF2","11.2.1HF4","11.2.0HF4","11.1.0HF6","11.0.0HF5","10.2.4HF6");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("11.0.0-11.3.0","10.0.0-10.2.4","9.0.0-9.6.1");
vmatrix["LTM"]["unaffected"] = make_list("11.4.0","11.3.0HF2","11.2.1HF4","11.2.0HF4","11.1.0HF6","11.0.0HF5","10.2.4HF6");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("11.3.0");
vmatrix["PEM"]["unaffected"] = make_list("11.4.0","11.3.0HF2");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("11.0.0-11.3.0","10.0.0-10.2.4","9.4.5-9.4.8");
vmatrix["PSM"]["unaffected"] = make_list("11.4.0","11.3.0HF2","11.2.1HF4","11.2.0HF4","11.1.0HF6","11.0.0HF5","10.2.4HF6");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("11.0.0-11.3.0","10.0.0-10.2.4","9.4.0-9.4.8");
vmatrix["WAM"]["unaffected"] = make_list("11.3.0HF2","11.2.1HF4","11.2.0HF4","11.1.0HF6","11.0.0HF5","10.2.4HF6");

# WOM
vmatrix["WOM"] = make_array();
vmatrix["WOM"]["affected"  ] = make_list("11.0.0-11.3.0","10.0.0-10.2.4");
vmatrix["WOM"]["unaffected"] = make_list("11.3.0HF2","11.2.1HF4","11.2.0HF4","11.1.0HF6","11.0.0HF5","10.2.4HF6");


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
