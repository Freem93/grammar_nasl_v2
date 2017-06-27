#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution SOL9990.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(80119);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/20 13:54:16 $");

  script_cve_id("CVE-2014-8727");
  script_bugtraq_id(71063);
  script_osvdb_id(114603);
  script_xref(name:"EDB-ID", value:"35222");

  script_name(english:"F5 Networks BIG-IP : Directory Traversal and File Deletion (ID 363027)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The 'properties.jsp' and 'tmui/Control/form' contain a flaw in how
user-supplied parameters are validated, specifically the 'name'
parameter. An authenticated user with the role of 'Resource
Administrator' or 'Administrator' can exploit this flaw to arbitrarily
enumerate and subsequently delete files on the system via standard
HTTP requests using directory traversal sequences.");
  # https://support.f5.com/kb/en-us/solutions/public/13000/100/sol13109.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c2087c03");
  script_set_attribute(attribute:"see_also", value:"http://www.exploit-db.com/exploits/35222/");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 10.2.2 Hotfix 2 / version 11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/19");

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
hotfix  = get_kb_item("Host/BIG-IP/hotfix");
if ( ! version ) audit(AUDIT_OS_NOT, "F5 Networks BIG-IP");
if ( isnull(hotfix) ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/hotfix");
if ( ! get_kb_item("Host/BIG-IP/modules") ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/modules");

vmatrix    = make_array();
affected   = make_list("10.1.0-10.2.2HF1");
unaffected = make_list("9","10.2.2HF2","11");
modules    = make_list(
  "GTM",
  "LTM",
  "ASM",
  "AM",
  "AFM",
  "LC",
  "WAM",
  "WOM",
  "AVR",
  "PSM",
  "APM"
);

foreach module (modules)
{
  vmatrix[module] = make_array();
  vmatrix[module]["affected"  ] = affected;
  vmatrix[module]["unaffected"] = unaffected;
}

if(hotfix != "0") version += 'HF'+hotfix;

if (bigip_is_affected(vmatrix:vmatrix, sol:"NONE"))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  BIGIP version : ' + version +
      '\n  Fixed version : 10.2.2HF2 / 11';
    security_warning(port:0, extra:report+'\n');
  }
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
