#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution SOL10509.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(78121);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/10/31 13:45:40 $");

  script_cve_id("CVE-2008-4609");
  script_bugtraq_id(31545);
  script_osvdb_id(62144);

  script_name(english:"F5 Networks BIG-IP : Sockstress DoS tool vulnerability (SOL10509)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sockstress DoS tool CVE-2008-4609. The TCP implementation in (1)
Linux, (2) platforms based on BSD Unix, (3) Microsoft Windows, (4)
Cisco products, and probably other operating systems allows remote
attackers to cause a denial of service (connection queue exhaustion)
via multiple vectors that manipulate information in the TCP state
table, as demonstrated by sockstress."
  );
  # http://support.f5.com/kb/en-us/solutions/public/10000/500/sol10509.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1e79a8e"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.cert.fi/haavoittuvuudet/2008/tcp-vulnerabilities.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution SOL10509."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/07");
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

sol = "SOL10509";
vmatrix = make_array();

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("9.3.0-9.3.1","9.4.0-9.4.8","10.0.0-10.0.1");
vmatrix["ASM"]["unaffected"] = make_list("10.1","10.2","11");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("9.3.0-9.3.1","9.4.0-9.4.8","10.0.0-10.0.1");
vmatrix["GTM"]["unaffected"] = make_list("10.1","10.2","11");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("9.3.0-9.3.1","9.4.0-9.4.8","10.0.0-10.0.1");
vmatrix["LC"]["unaffected"] = make_list("10.1","10.2","11");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("9.3.0-9.3.1","9.4.0-9.4.8","9.6.0-9.6.1","10.0.0-10.0.1");
vmatrix["LTM"]["unaffected"] = make_list("10.1","10.2","11");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("9.4.5-9.4.8","10.0.0-10.0.1");
vmatrix["PSM"]["unaffected"] = make_list("10.1","10.2","11");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("9.4.0-9.4.8","10.0.0-10.0.1");
vmatrix["WAM"]["unaffected"] = make_list("10.1","10.2","11");

# WOM
vmatrix["WOM"] = make_array();
vmatrix["WOM"]["affected"  ] = make_list("10.0.0-10.0.1");
vmatrix["WOM"]["unaffected"] = make_list("10.1","10.2","11");


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
