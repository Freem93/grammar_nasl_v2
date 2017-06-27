#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2016/04/11. Vendor decided CVE-2015-4736 did not apply
# to BIG-IP products.

include("compat.inc");

if (description)
{
  script_id(85658);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/04/13 20:14:10 $");

  script_cve_id("CVE-2015-4736");
  script_bugtraq_id(75850);
  script_osvdb_id(124624);

  script_name(english:"F5 Networks BIG-IP : Java vulnerability (SOL17170) (deprecated)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Unspecified vulnerability in Oracle Java SE 7u80 and 8u45 allows
remote attackers to affect confidentiality, integrity, and
availability via unknown vectors related to Deployment.

Vendor decided CVE-2015-4736 did not apply to BIG-IP products so the
plugin has been deprecated."
  );
  # http://support.f5.com/kb/en-us/solutions/public/17000/100/sol17170.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2bd4bb5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"n/a"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"F5 Networks Local Security Checks");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version");

  exit(0);
}

exit(0, 'This plugin has been deprecated. Vendor decided CVE-2015-4736 did not\napply to BIG-IP products.');

include("f5_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
version = get_kb_item("Host/BIG-IP/version");
if ( ! version ) audit(AUDIT_OS_NOT, "F5 Networks BIG-IP");
if ( isnull(get_kb_item("Host/BIG-IP/hotfix")) ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/hotfix");
if ( ! get_kb_item("Host/BIG-IP/modules") ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/modules");

sol = "SOL17170";
vmatrix = make_array();

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("12.0.0","11.5.0-11.6.0");
vmatrix["AFM"]["unaffected"] = make_list("11.3.0-11.4.1");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("12.0.0","11.5.0-11.6.0");
vmatrix["AM"]["unaffected"] = make_list("11.4.0-11.4.1");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("12.0.0","11.5.0-11.6.0");
vmatrix["APM"]["unaffected"] = make_list("11.0.0-11.4.1","10.1.0-10.2.4");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("12.0.0","11.5.0-11.6.0");
vmatrix["ASM"]["unaffected"] = make_list("11.0.0-11.4.1","10.1.0-10.2.4");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("12.0.0","11.5.0-11.6.0");
vmatrix["AVR"]["unaffected"] = make_list("11.0.0-11.4.1");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.5.0-11.6.0");
vmatrix["GTM"]["unaffected"] = make_list("11.0.0-11.4.1","10.1.0-10.2.4");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("12.0.0","11.5.0-11.6.0");
vmatrix["LC"]["unaffected"] = make_list("11.0.0-11.4.1","10.1.0-10.2.4");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("12.0.0","11.5.0-11.6.0");
vmatrix["LTM"]["unaffected"] = make_list("11.0.0-11.4.1","10.1.0-10.2.4");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("12.0.0","11.5.0-11.6.0");
vmatrix["PEM"]["unaffected"] = make_list("11.3.0-11.4.1");


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
