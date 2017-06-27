#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution SOL15629.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(78197);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/11/01 18:40:34 $");

  script_cve_id("CVE-2014-6271", "CVE-2014-6277", "CVE-2014-6278", "CVE-2014-7169", "CVE-2014-7186", "CVE-2014-7187");
  script_bugtraq_id(70103, 70137, 70152, 70154, 70165, 70166);
  script_osvdb_id(112004, 112096, 112097, 112158);
  script_xref(name:"IAVA", value:"2014-A-0142");

  script_name(english:"F5 Networks BIG-IP : Multiple GNU Bash vulnerabilities (SOL15629) (Shellshock)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"GNU Bash through 4.3 processes trailing strings after function
definitions in the values of environment variables, which allows
remote attackers to execute arbitrary code via a crafted environment,
as demonstrated by vectors involving the ForceCommand feature in
OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP
Server, scripts executed by unspecified DHCP clients, and other
situations in which setting the environment occurs across a privilege
boundary from Bash execution."
  );
  # http://support.f5.com/kb/en-us/solutions/public/15000/600/sol15629.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?551783c1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.f5.com/shellshock"
  );
  # https://devcentral.f5.com/articles/3-ways-to-use-big-ip-asm-to-mitigate-shellshock
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8374474"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://devcentral.f5.com/articles/cve-2014-6271-shellshocked"
  );
  # https://devcentral.f5.com/articles/shellshock-mitigation-with-big-ip-irules
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?658e7e22"
  );
  # https://devcentral.f5.com/articles/shellshock-mitigation-with-linerate-proxy
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?48d59554"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution SOL15629."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CUPS Filter Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/25");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/10");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

sol = "SOL15629";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("11.6.0","11.3.0-11.5.1");
vmatrix["AFM"]["unaffected"] = make_list("11.6.0HF1","11.5.2-11.5.3","11.5.1HF5","11.5.0HF5","11.4.1HF5","11.4.0HF8","11.3.0HF10");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("11.6.0","11.4.0-11.5.1");
vmatrix["AM"]["unaffected"] = make_list("11.6.0HF1","11.5.2-11.5.3","11.5.1HF5","11.5.0HF5","11.4.1HF5","11.4.0HF8");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("11.6.0","11.0.0-11.5.1","10.1.0-10.2.4");
vmatrix["APM"]["unaffected"] = make_list("11.6.0HF1","11.5.2-11.5.3","11.5.1HF5","11.5.0HF5","11.4.1HF5","11.4.0HF8","11.3.0HF10","11.2.1HF12","10.2.4HF9");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("11.6.0","11.0.0-11.5.1","10.0.0-10.2.4");
vmatrix["ASM"]["unaffected"] = make_list("11.6.0HF1","11.5.2-11.5.3","11.5.1HF5","11.5.0HF5","11.4.1HF5","11.4.0HF8","11.3.0HF10","11.2.1HF12","10.2.4HF9");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("11.6.0","11.0.0-11.5.1");
vmatrix["AVR"]["unaffected"] = make_list("11.6.0HF1","11.5.2-11.5.3","11.5.1HF5","11.5.0HF5","11.4.1HF5","11.4.0HF8","11.3.0HF10","11.2.1HF12");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.6.0","11.0.0-11.5.1","10.0.0-10.2.4");
vmatrix["GTM"]["unaffected"] = make_list("11.6.0HF1","11.5.2-11.5.3","11.5.1HF5","11.5.0HF5","11.4.1HF5","11.4.0HF8","11.3.0HF10","11.2.1HF12","10.2.4HF9");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("11.6.0","11.0.0-11.5.1","10.0.0-10.2.4");
vmatrix["LC"]["unaffected"] = make_list("11.6.0HF1","11.5.2-11.5.3","11.5.1HF5","11.5.0HF5","11.4.1HF5","11.4.0HF8","11.3.0HF10","11.2.1HF12","10.2.4HF9");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("11.6.0","11.0.0-11.5.1","10.0.0-10.2.4");
vmatrix["LTM"]["unaffected"] = make_list("11.6.0HF1","11.5.2-11.5.3","11.5.1HF5","11.5.0HF5","11.4.1HF5","11.4.0HF8","11.3.0HF10","11.2.1HF12","10.2.4HF9");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("11.6.0","11.3.0-11.5.1");
vmatrix["PEM"]["unaffected"] = make_list("11.6.0HF1","11.5.2-11.5.3","11.5.1HF5","11.5.0HF5","11.4.1HF5","11.3.0HF10");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("11.0.0-11.4.1","10.0.0-10.2.4");
vmatrix["PSM"]["unaffected"] = make_list("11.4.1HF5","11.4.0HF8","11.3.0HF10","11.2.1HF12","10.2.4HF9");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("11.0.0-11.3.0","10.0.0-10.2.4");
vmatrix["WAM"]["unaffected"] = make_list("11.3.0HF10","11.2.1HF12","10.2.4HF9");

# WOM
vmatrix["WOM"] = make_array();
vmatrix["WOM"]["affected"  ] = make_list("11.0.0-11.3.0","10.0.0-10.2.4");
vmatrix["WOM"]["unaffected"] = make_list("11.3.0HF10","11.2.1HF12","10.2.4HF9");


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
