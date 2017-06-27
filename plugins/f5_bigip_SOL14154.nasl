#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution SOL14154.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(78141);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/10/31 13:45:41 $");

  script_cve_id("CVE-2012-3000");
  script_bugtraq_id(57500);
  script_osvdb_id(89446);

  script_name(english:"F5 Networks BIG-IP : SQL injection vulnerability from an authenticated source (SOL14154)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A SQL injection vulnerability exists in a BIG-IP component. This local
vulnerability may allow an authenticated attacker to download
arbitrary files from the file system."
  );
  # http://support.f5.com/kb/en-us/solutions/public/14000/100/sol14154.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?da38e7b1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.sec-consult.com"
  );
  # https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20121203-0_F5_FirePass_SSL_VPN_Local_File_Inclusion_v10.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2d85aefc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution SOL14154."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/23");
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

sol = "SOL14154";
vmatrix = make_array();

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("11.0.0-11.2.1");
vmatrix["APM"]["unaffected"] = make_list("10.0.1-10.2.4","11.2.0HF3","11.2.1HF3","11.3.0-11.4.0");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("11.0.0-11.2.1");
vmatrix["ASM"]["unaffected"] = make_list("9.4.6-9.4.8","10.0.1-10.2.4","11.2.0HF3","11.2.1HF3","11.3.0-11.4.0");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("11.0.0-11.2.1");
vmatrix["AVR"]["unaffected"] = make_list("11.2.0HF3","11.2.1HF3","11.3.0-11.4.0");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.0.0-11.2.1");
vmatrix["GTM"]["unaffected"] = make_list("9.4.6-9.4.8","10.0.1-10.2.4","11.2.0HF3","11.2.1HF3","11.3.0-11.4.0");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("11.0.0-11.2.1");
vmatrix["LC"]["unaffected"] = make_list("9.4.6-9.4.8","10.0.1-10.2.4","11.2.0HF3","11.2.1HF3","11.3.0-11.4.0");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("11.0.0-11.2.1");
vmatrix["LTM"]["unaffected"] = make_list("9.4.6-9.4.8","10.0.1-10.2.4","11.2.0HF3","11.2.1HF3","11.3.0-11.4.0");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("11.0.0-11.2.1");
vmatrix["PSM"]["unaffected"] = make_list("9.4.6-9.4.8","10.0.1-10.2.4","11.2.0HF3","11.2.1HF3","11.3.0-11.4.0");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("11.0.0-11.2.1");
vmatrix["WAM"]["unaffected"] = make_list("9.4.6-9.4.8","10.0.1-10.2.4","11.2.0HF3","11.2.1HF3","11.3.0");

# WOM
vmatrix["WOM"] = make_array();
vmatrix["WOM"]["affected"  ] = make_list("11.0.0-11.2.1");
vmatrix["WOM"]["unaffected"] = make_list("10.0.1-10.2.4","11.2.0HF3","11.2.1HF3","11.3.0");


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
