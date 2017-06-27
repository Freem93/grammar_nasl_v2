#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution SOL17047.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(85518);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/10/31 13:45:42 $");

  script_cve_id("CVE-2015-5058");
  script_osvdb_id(126470);

  script_name(english:"F5 Networks BIG-IP : ICMP packet processing vulnerability (SOL17047)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Memory leak in the virtual server component in F5 Big-IP LTM, AAM,
AFM, Analytics, APM, ASM, GTM, Link Controller, and PEM 11.5.x before
11.5.1 HF10, 11.5.3 before HF1, and 11.6.0 before HF5, BIG-IQ Cloud,
Device, and Security 4.4.0 through 4.5.0, and BIG-IQ ADC 4.5.0 allows
remote attackers to cause a denial of service (memory consumption) via
a large number of crafted ICMP packets."
  );
  # http://support.f5.com/kb/en-us/solutions/public/17000/000/sol17047.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d622d78a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution SOL17047."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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

sol = "SOL17047";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("11.5.0-11.6.0");
vmatrix["AFM"]["unaffected"] = make_list("12.0.0","11.6.0HF5","11.5.4","11.5.3HF1","11.5.1HF10","11.3.0-11.4.1");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("11.5.0-11.6.0");
vmatrix["AM"]["unaffected"] = make_list("12.0.0","11.6.0HF5","11.5.4","11.5.3HF1","11.5.1HF10","11.4.0-11.4.1");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("11.5.0-11.6.0");
vmatrix["APM"]["unaffected"] = make_list("12.0.0","11.6.0HF5","11.5.4","11.5.3HF1","11.5.1HF10","10.1.0-11.4.1");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("11.5.0-11.6.0");
vmatrix["ASM"]["unaffected"] = make_list("12.0.0","11.6.0HF5","11.5.4","11.5.3HF1","11.5.1HF10","10.1.0-11.4.1");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("11.5.0-11.6.0");
vmatrix["AVR"]["unaffected"] = make_list("12.0.0","11.6.0HF5","11.5.4","11.5.3HF1","11.5.1HF10","11.0.0-11.4.1");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.5.0-11.6.0");
vmatrix["GTM"]["unaffected"] = make_list("11.6.0HF5","11.5.4","11.5.3HF1","11.5.1HF10","10.1.0-11.4.1");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("11.5.0-11.6.0");
vmatrix["LC"]["unaffected"] = make_list("12.0.0","11.6.0HF5","11.5.4","11.5.3HF1","11.5.1HF10","10.1.0-11.4.1");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("11.5.0-11.6.0");
vmatrix["LTM"]["unaffected"] = make_list("12.0.0","11.6.0HF5","11.5.4","11.5.3HF1","11.5.1HF10","10.1.0-11.4.1");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("11.5.0-11.6.0");
vmatrix["PEM"]["unaffected"] = make_list("12.0.0","11.6.0HF5","11.5.4","11.5.3HF1","11.5.1HF10","11.3.0-11.4.1");


if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  if (report_verbosity > 0) security_hole(port:0, extra:bigip_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = bigip_get_tested_modules();
  audit_extra = "For BIG-IP module(s) " + tested + ",";
  if (tested) audit(AUDIT_INST_VER_NOT_VULN, audit_extra, version);
  else audit(AUDIT_HOST_NOT, "running any of the affected modules");
}
