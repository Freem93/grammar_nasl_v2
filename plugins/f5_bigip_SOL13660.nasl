#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution SOL13660.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(86003);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/10/31 13:45:41 $");

  script_cve_id("CVE-2012-1667");
  script_bugtraq_id(53772);
  script_osvdb_id(82609);

  script_name(english:"F5 Networks BIG-IP : BIND vulnerability (SOL13660)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ISC BIND 9.x before 9.7.6-P1, 9.8.x before 9.8.3-P1, 9.9.x before
9.9.1-P1, and 9.4-ESV and 9.6-ESV before 9.6-ESV-R7-P1 does not
properly handle resource records with a zero-length RDATA section,
which allows remote DNS servers to cause a denial-of-service (DoS)
(process crash or data corruption) or obtain sensitive information
from process memory by way of a crafted record. (CVE-2012-1667)"
  );
  # http://support.f5.com/kb/en-us/solutions/public/13000/600/sol13660.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6008904b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.f5.com/kb/en-us/solutions/public/6000/900/sol6963.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.isc.org/products/BIND/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.isc.org/software/bind/advisories/cve-2012-1667"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution SOL13660."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/18");
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

sol = "SOL13660";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("11.0.0-11.2.0","10.1.0-10.2.4");
vmatrix["APM"]["unaffected"] = make_list("11.2.1-11.4.0","11.2.0HF1","11.1.0HF4","11.0.0HF3","10.2.4HF3");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("11.0.0-11.2.0","10.0.0-10.2.4","9.4.8");
vmatrix["ASM"]["unaffected"] = make_list("11.2.1-11.4.0","11.2.0HF1","11.1.0HF4","11.0.0HF3","10.2.4HF3","9.4.8HF6");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.0.0-11.2.0","10.0.0-10.2.4","9.4.8");
vmatrix["GTM"]["unaffected"] = make_list("11.2.1-11.4.0","11.2.0HF1","11.1.0HF4","11.0.0HF3","10.2.4HF3","9.4.8HF6");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("11.0.0-11.2.0","10.0.0-10.2.4","9.4.8");
vmatrix["LC"]["unaffected"] = make_list("11.2.1-11.4.0","11.2.0HF1","11.1.0HF4","11.0.0HF3","10.2.4HF3","9.4.8HF6");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("11.0.0-11.2.0","10.0.0-10.2.4","9.4.8");
vmatrix["LTM"]["unaffected"] = make_list("11.2.1-11.4.0","11.2.0HF1","11.1.0HF4","11.0.0HF3","10.2.4HF3","9.4.8HF6");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("11.0.0-11.2.0","10.0.0-10.2.4","9.4.8");
vmatrix["PSM"]["unaffected"] = make_list("11.2.1-11.4.0","11.2.0HF1","11.1.0HF4","11.0.0HF3","10.2.4HF3","9.4.8HF6");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("11.0.0-11.2.0","10.0.0-10.2.4","9.4.8");
vmatrix["WAM"]["unaffected"] = make_list("11.2.1-11.3.0","11.2.0HF1","11.1.0HF4","11.0.0HF3","10.2.4HF3","9.4.8HF6");

# WOM
vmatrix["WOM"] = make_array();
vmatrix["WOM"]["affected"  ] = make_list("11.0.0-11.2.0","10.0.0-10.2.4");
vmatrix["WOM"]["unaffected"] = make_list("11.2.1-11.3.0","11.2.0HF1","11.1.0HF4","11.0.0HF3","10.2.4HF3");


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
