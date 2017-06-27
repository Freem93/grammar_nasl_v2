#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K16389.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(82672);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/04/10 13:19:30 $");

  script_cve_id("CVE-2013-5908", "CVE-2014-0386", "CVE-2014-0393", "CVE-2014-0401", "CVE-2014-0402", "CVE-2014-0412", "CVE-2014-0437");
  script_bugtraq_id(64849, 64877, 64880, 64896, 64898, 64904, 64908);
  script_osvdb_id(102078);

  script_name(english:"F5 Networks BIG-IP : Multiple MySQL vulnerabilities (K16389)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2013-5908 Unspecified vulnerability in the MySQL Server component
in Oracle MySQL 5.1.72 and earlier, 5.5.34 and earlier, and 5.6.14 and
earlier allows remote attackers to affect availability via unknown
vectors related to Error Handling.

CVE-2014-0401 Unspecified vulnerability in the MySQL Server component
in Oracle MySQL 5.1.72 and earlier, 5.5.34 and earlier, and 5.6.14 and
earlier allows remote authenticated users to affect availability via
unknown vectors.

CVE-2014-0437 Unspecified vulnerability in the MySQL Server component
in Oracle MySQL 5.1.72 and earlier, 5.5.34 and earlier, and 5.6.14 and
earlier allows remote authenticated users to affect availability via
unknown vectors related to Optimizer.

CVE-2014-0393 Unspecified vulnerability in the MySQL Server component
in Oracle MySQL 5.1.71 and earlier, 5.5.33 and earlier, and 5.6.13 and
earlier allows remote authenticated users to affect integrity via
unknown vectors related to InnoDB.

CVE-2014-0386 Unspecified vulnerability in the MySQL Server component
in Oracle MySQL 5.1.71 and earlier, 5.5.33 and earlier, and 5.6.13 and
earlier allows remote authenticated users to affect availability via
unknown vectors related to Optimizer.

CVE-2014-0412 Unspecified vulnerability in the MySQL Server component
in Oracle MySQL 5.1.72 and earlier, 5.5.34 and earlier, and 5.6.14 and
earlier allows remote authenticated users to affect availability via
unknown vectors related to InnoDB.

CVE-2014-0402 Unspecified vulnerability in the MySQL Server component
in Oracle MySQL 5.1.71 and earlier, 5.5.33 and earlier, and 5.6.13 and
earlier allows remote authenticated users to affect availability via
unknown vectors related to Locking."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/#/article/K16389"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K16389."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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

sol = "K16389";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("11.3.0-11.5.2");
vmatrix["AFM"]["unaffected"] = make_list("11.6.0");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("11.4.0-11.5.2");
vmatrix["AM"]["unaffected"] = make_list("11.6.0");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("11.0.0-11.5.2","10.1.0-10.2.4");
vmatrix["APM"]["unaffected"] = make_list("11.6.0");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("11.0.0-11.5.2","10.0.0-10.2.4");
vmatrix["ASM"]["unaffected"] = make_list("11.6.0");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("11.0.0-11.5.2");
vmatrix["AVR"]["unaffected"] = make_list("11.6.0");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.0.0-11.5.2","10.0.0-10.2.4");
vmatrix["GTM"]["unaffected"] = make_list("11.6.0");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("11.0.0-11.5.2","10.0.0-10.2.4");
vmatrix["LC"]["unaffected"] = make_list("11.6.0");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("11.0.0-11.5.2","10.0.0-10.2.4");
vmatrix["LTM"]["unaffected"] = make_list("11.6.0");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("11.3.0-11.5.2");
vmatrix["PEM"]["unaffected"] = make_list("11.6.0");


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
