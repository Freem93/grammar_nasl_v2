#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution SOL15564.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(78195);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/10/31 13:45:41 $");

  script_cve_id("CVE-2014-3511");
  script_bugtraq_id(69079);

  script_name(english:"F5 Networks BIG-IP : TLS vulnerability (SOL15564)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The ssl23_get_client_hello function in s23_srvr.c in OpenSSL 1.0.1
before 1.0.1i allows man-in-the-middle attackers to force the use of
TLS 1.0 by triggering ClientHello message fragmentation in
communication between a client and server that both support later TLS
versions, related to a 'protocol downgrade' issue."
  );
  # http://support.f5.com/kb/en-us/solutions/public/15000/500/sol15564.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5071e5a7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution SOL15564."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

sol = "SOL15564";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("11.6.0","11.5.0","11.5.1");
vmatrix["AFM"]["unaffected"] = make_list("12.0.0","11.6.0HF4","11.5.2","11.5.1HF6","11.3.0-11.4.1");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("11.6.0","11.5.0","11.5.1");
vmatrix["AM"]["unaffected"] = make_list("12.0.0","11.6.0HF4","11.5.2","11.5.1HF6","11.4.0-11.4.1");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("11.6.0","11.5.0","11.5.1");
vmatrix["APM"]["unaffected"] = make_list("12.0.0","11.6.0HF4","11.5.2","11.5.1HF6","11.0.0-11.4.1","10.1.0-10.2.4");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("11.6.0","11.5.0","11.5.1");
vmatrix["ASM"]["unaffected"] = make_list("12.0.0","11.6.0HF4","11.5.2","11.5.1HF6","11.0.0-11.4.1","10.0.0-10.2.4");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("11.6.0","11.5.0","11.5.1");
vmatrix["AVR"]["unaffected"] = make_list("12.0.0","11.6.0HF4","11.5.2","11.5.1HF6","11.0.0-11.4.1");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.6.0","11.5.0","11.5.1");
vmatrix["GTM"]["unaffected"] = make_list("11.6.0HF4","11.5.2","11.5.1HF6","11.0.0-11.4.1","10.0.0-10.2.4");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("11.6.0","11.5.0","11.5.1");
vmatrix["LC"]["unaffected"] = make_list("12.0.0","11.6.0HF4","11.5.2","11.5.1HF6","11.0.0-11.4.1","10.0.0-10.2.4");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("11.6.0","11.5.0","11.5.1");
vmatrix["LTM"]["unaffected"] = make_list("12.0.0","11.6.0HF4","11.5.2","11.5.1HF6","11.0.0-11.4.1","10.0.0-10.2.4");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("11.6.0","11.5.0","11.5.1");
vmatrix["PEM"]["unaffected"] = make_list("12.0.0","11.6.0HF4","11.5.2","11.5.1HF6","11.3.0-11.4.1");


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
