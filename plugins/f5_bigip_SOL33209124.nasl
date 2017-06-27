#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2016/03/15, advisory updated to remove all affected
# versions plugin covered.
#

include("compat.inc");

if (description)
{
  script_id(88850);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/04/26 04:40:46 $");

  script_cve_id("CVE-2015-3197");

  script_name(english:"F5 Networks BIG-IP : OpenSSL vulnerability (SOL33209124) (deprecated)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ssl/s2_srvr.c in OpenSSL 1.0.1 before 1.0.1r and 1.0.2 before 1.0.2f
does not prevent use of disabled ciphers, which makes it easier for
man-in-the-middle attackers to defeat cryptographic protection
mechanisms by performing computations on SSLv2 traffic, related to the
get_client_master_key and get_client_hello functions.

This plugin has been deprecated. The advisory was updated to remove
all affected versions the plugin covered."
  );
  # http://support.f5.com/kb/en-us/solutions/public/33209000/100/sol33209124.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b0b8821d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"n/a"
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:protocol_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:web_accelerator_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"F5 Networks Local Security Checks");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version", "Settings/ParanoidReport");

  exit(0);
}

exit(0, "This plugin has been deprecated. The advisory was updated to remove all affected versions the plugin covered.");

include("f5_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
version = get_kb_item("Host/BIG-IP/version");
if ( ! version ) audit(AUDIT_OS_NOT, "F5 Networks BIG-IP");
if ( isnull(get_kb_item("Host/BIG-IP/hotfix")) ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/hotfix");
if ( ! get_kb_item("Host/BIG-IP/modules") ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/modules");

sol = "SOL33209124";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("10.1.0-10.2.2");
vmatrix["APM"]["unaffected"] = make_list("12.0.0","11.0.0-11.6.0","10.2.3-10.2.4");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("10.1.0-10.2.2");
vmatrix["ASM"]["unaffected"] = make_list("12.0.0","11.0.0-11.6.0","10.2.3-10.2.4");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("10.1.0-10.2.2");
vmatrix["GTM"]["unaffected"] = make_list("11.0.0-11.6.0","10.2.3-10.2.4");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("10.1.0-10.2.2");
vmatrix["LC"]["unaffected"] = make_list("12.0.0","11.0.0-11.6.0","10.2.3-10.2.4");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("10.1.0-10.2.2");
vmatrix["LTM"]["unaffected"] = make_list("12.0.0","11.0.0-11.6.0","10.2.3-10.2.4");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("10.1.0-10.2.2");
vmatrix["PSM"]["unaffected"] = make_list("11.0.0-11.4.1","10.2.3-10.2.4");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("10.1.0-10.2.2");
vmatrix["WAM"]["unaffected"] = make_list("11.0.0-11.3.0","10.2.3-10.2.4");

# WOM
vmatrix["WOM"] = make_array();
vmatrix["WOM"]["affected"  ] = make_list("10.1.0-10.2.2");
vmatrix["WOM"]["unaffected"] = make_list("11.0.0-11.3.0","10.2.3-10.2.4");


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
