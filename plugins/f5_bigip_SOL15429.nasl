# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a security fix.
#
# Disabled on 2014/10/20.
#

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution SOL15429.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(78186);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/10/20 13:46:20 $");

  script_cve_id("CVE-2014-0119");
  script_bugtraq_id(67669);

  script_name(english:"F5 Networks BIG-IP : Apache Tomcat vulnerability (SOL15429)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Apache Tomcat before 6.0.40, 7.x before 7.0.54, and 8.x before 8.0.6
does not properly constrain the class loader that accesses the XML
parser used with an XSLT stylesheet, which allows remote attackers to
(1) read arbitrary files via a crafted web application that provides
an XML external entity declaration in conjunction with an entity
reference, related to an XML External Entity (XXE) issue, or (2) read
files associated with different web applications on a single Tomcat
instance via a crafted web application."
  );
  # http://support.f5.com/kb/en-us/solutions/public/15000/400/sol15429.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?703212ca"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution SOL15429."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:protocol_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip:web_accelerator_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"F5 Networks Local Security Checks");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version");

  exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a security fix.");



include("f5_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
version = get_kb_item("Host/BIG-IP/version");
if ( ! version ) audit(AUDIT_OS_NOT, "F5 Networks BIG-IP");
if ( isnull(get_kb_item("Host/BIG-IP/hotfix")) ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/hotfix");
if ( ! get_kb_item("Host/BIG-IP/modules") ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/modules");

sol = "SOL15429";
vmatrix = make_array();

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("11.3.0-11.5.1");
vmatrix["AFM"]["unaffected"] = make_list("11.6.0");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("11.0.0-11.5.1");
vmatrix["AVR"]["unaffected"] = make_list("11.6.0");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("11.0.0-11.5.1","10.0.0-10.2.4");
vmatrix["LC"]["unaffected"] = make_list("11.6.0");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("11.0.0-11.5.1","10.1.0-10.2.4");
vmatrix["APM"]["unaffected"] = make_list("11.6.0");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.0.0-11.5.1","10.0.0-10.2.4");
vmatrix["GTM"]["unaffected"] = make_list("11.6.0");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("11.0.0-11.5.1","10.0.0-10.2.4");
vmatrix["LTM"]["unaffected"] = make_list("11.6.0");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("11.3.0-11.5.1");
vmatrix["PEM"]["unaffected"] = make_list("11.6.0");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("11.0.0-11.5.1","10.0.0-10.2.4");
vmatrix["ASM"]["unaffected"] = make_list("11.6.0");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("11.4.0-11.5.1");
vmatrix["AM"]["unaffected"] = make_list("11.6.0");


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
