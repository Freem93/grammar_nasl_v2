#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81597);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/03/03 14:33:19 $");

  script_cve_id("CVE-2015-1050");
  script_bugtraq_id(72014);
  script_osvdb_id(116987);

  script_name(english:"F5 Networks BIG-IP : ASM < 11.6.0 Response Body XSS");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The F5 Networks Application Security Manager (ASM) running on the
remote device is prior to version 11.6.0. It is, therefore, affected
by a cross-site scripting vulnerability due to improper validation of
user-supplied input to the 'Response Body' field when a new user
account is being created. A remote attacker can exploit this to inject
HTML or arbitrary web script, which then can be run by an
administrative account using the 'Show' button in the management
console.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2015/Jan/40");
  script_set_attribute(attribute:"solution", value:"Upgrade ASM to version 11.6.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/02");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"F5 Networks Local Security Checks");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/modules", "Host/BIG-IP/version");

  exit(0);
}


include("f5_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
version = get_kb_item("Host/BIG-IP/version");
if ( ! version ) audit(AUDIT_OS_NOT, "F5 Networks BIG-IP");
if ( ! get_kb_item("Host/BIG-IP/modules") ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/modules");

# This has no SOL.
vmatrix = make_array();

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("11.4.0-11.5.1");
vmatrix["ASM"]["unaffected"] = make_list("11.6.0");

if (bigip_is_affected(vmatrix:vmatrix))
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
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
