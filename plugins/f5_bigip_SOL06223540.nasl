#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K06223540.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(89973);
  script_version("$Revision: 2.14 $");
  script_cvs_date("$Date: 2017/03/15 20:36:15 $");

  script_cve_id("CVE-2015-8240");
  script_osvdb_id(136042);

  script_name(english:"F5 Networks BIG-IP : F5 TCP vulnerability (K06223540)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Traffic Management Microkernel (TMM) in F5 BIG-IP LTM, AAM, AFM,
Analytics, APM, ASM, GTM, Link Controller, and BIG-IP PEM before
11.4.1 HF10, 11.5.x before 11.5.4, and 11.6.x before 11.6.0 HF6 and
BIG-IP PSM before 11.4.1 HF10 does not properly handle TCP options,
which allows remote attackers to cause a denial-of-service (DoS)
through unspecified vectors, related to the tm.minpathmtu database
variable. (CVE-2015-8240)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/#/article/K06223540"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K06223540."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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

sol = "K06223540";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("11.6.0HF5","11.5.3HF2","11.4.1HF9");
vmatrix["AFM"]["unaffected"] = make_list("12.0.0","11.6.1","11.6.0HF6","11.6.0-11.6.0HF4","11.5.4","11.5.0-11.5.3HF1","11.4.1HF10","11.3.0-11.4.1HF8");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("11.6.0HF5","11.5.3HF2","11.4.1HF9");
vmatrix["AM"]["unaffected"] = make_list("12.0.0","11.6.1","11.6.0HF6","11.6.0-11.6.0HF4","11.5.4","11.5.0-11.5.3HF1","11.4.1HF10","11.4.0-11.4.1HF8");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("11.6.0HF5","11.5.3HF2","11.4.1HF9");
vmatrix["APM"]["unaffected"] = make_list("12.0.0","11.6.1","11.6.0HF6","11.6.0-11.6.0HF4","11.5.4","11.5.0-11.5.3HF1","11.4.1HF10","11.0.0-11.4.1HF8","11.2.1HF16","10.2.4HF13","10.1.0-10.2.4HF12");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("11.6.0HF5","11.5.3HF2","11.4.1HF9");
vmatrix["ASM"]["unaffected"] = make_list("12.0.0","11.6.1","11.6.0HF6","11.6.0-11.6.0HF4","11.5.4","11.5.0-11.5.3HF1","11.4.1HF10","11.2.1HF16","11.0.0-11.4.1HF8","10.2.4HF13","10.1.0-10.2.4HF12");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("11.6.0HF5","11.5.3HF2","11.4.1HF9");
vmatrix["AVR"]["unaffected"] = make_list("12.0.0","11.6.1","11.6.0HF6","11.6.0-11.6.0HF4","11.5.4","11.5.0-11.5.3HF1","11.4.1HF10","11.2.1HF16","11.0.0-11.4.1HF8");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.6.0HF5","11.5.3HF2","11.4.1HF9");
vmatrix["GTM"]["unaffected"] = make_list("11.6.1","11.6.0HF6","11.6.0-11.6.0HF4","11.5.4","11.5.0-11.5.3HF1","11.4.1HF10","11.2.1HF16","11.0.0-11.4.1HF8","10.2.4HF13","10.1.0-10.2.4HF12");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("11.6.0HF5","11.5.3HF2","11.4.1HF9");
vmatrix["LC"]["unaffected"] = make_list("12.0.0","11.6.1","11.6.0HF6","11.6.0-11.6.0HF4","11.5.4","11.5.0-11.5.3HF1","11.4.1HF10","11.2.1HF16","11.0.0-11.4.1HF8","10.2.4HF13","10.1.0-10.2.4HF12");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("11.6.0HF5","11.5.3HF2","11.4.1HF9");
vmatrix["LTM"]["unaffected"] = make_list("12.0.0","11.6.1","11.6.0HF6","11.6.0-11.6.0HF4","11.5.4","11.5.0-11.5.3HF1","11.4.1HF10","11.2.1HF16","11.0.0-11.4.1HF8","10.2.4HF13","10.1.0-10.2.4HF12");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("11.6.0HF5","11.5.3HF2","11.4.1HF9");
vmatrix["PEM"]["unaffected"] = make_list("12.0.0","11.6.1","11.6.0HF6","11.6.0-11.6.0HF4","11.5.4","11.5.0-11.5.3HF1","11.4.1HF10","11.3.0-11.4.1HF8");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("11.4.1HF9");
vmatrix["PSM"]["unaffected"] = make_list("11.4.1HF10","11.0.0-11.4.1HF8","10.2.4HF13","10.1.0-10.2.4HF12");


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
