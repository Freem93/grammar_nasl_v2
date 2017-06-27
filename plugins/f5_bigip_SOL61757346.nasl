#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K61757346.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(100331);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/23 14:39:44 $");

  script_cve_id("CVE-2017-6131");

  script_name(english:"F5 Networks BIG-IP : BIG-IP Azure cloud vulnerability (K61757346)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"In some circumstances, a BIG-IP Azure cloud instance may contain a
default administrative password which can be used to remotely log in
to the BIG-IP system.

The affected administrative account is the Azure instance
administrative user created at deployment. The root and admin accounts
are not vulnerable.

This issue only affects BIG-IP Virtual Edition (VE) Azure instances
and Azure Web Application Firewall solutions on the Azure Marketplace.
This issue does not affect BIG-IP VE instances on any other cloud
services. All BIG-IP VE Azure instances licensed for any product are
affected by this vulnerability, except :

Instances deployed using solution templates.

Instances deployed using a password rather than public key for the
user-defined account during provisioning.

Note : For more information about deploying instances using solution
templates, refer to the DevCentral Deploy BIG-IP VE in Microsoft Azure
Using an ARM Template article. A DevCentral login is required to
access this content."
  );
  # https://devcentral.f5.com/articles/deploy-big-ip-ve-in-microsoft-azure-using-an-arm-template-26128
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ced7282b"
  );
  # https://first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:W/RC:C
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e9fb454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/#/article/K61757346"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K61757346."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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

sol = "K61757346";
vmatrix = make_array();

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2");
vmatrix["AFM"]["unaffected"] = make_list("13.0.0HF2","12.1.2HF1","11.4.0-11.6.1");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2");
vmatrix["AM"]["unaffected"] = make_list("13.0.0HF2","12.1.2HF1","11.4.0-11.6.1");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2");
vmatrix["APM"]["unaffected"] = make_list("13.0.0HF2","12.1.2HF1","11.4.0-11.6.1","11.2.1");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2");
vmatrix["LC"]["unaffected"] = make_list("13.0.0HF2","12.1.2HF1","11.4.0-11.6.1","11.2.1");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2");
vmatrix["LTM"]["unaffected"] = make_list("13.0.0HF2","12.1.2HF1","11.4.0-11.6.1","11.2.1");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("13.0.0","12.0.0-12.1.2");
vmatrix["PEM"]["unaffected"] = make_list("13.0.0HF2","12.1.2HF1","11.4.0-11.6.1");


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
