#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K14410.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(78149);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/03/15 20:36:15 $");

  script_cve_id("CVE-2011-2262", "CVE-2012-0075", "CVE-2012-0087", "CVE-2012-0101", "CVE-2012-0102", "CVE-2012-0112", "CVE-2012-0113", "CVE-2012-0114", "CVE-2012-0115", "CVE-2012-0116", "CVE-2012-0117", "CVE-2012-0118", "CVE-2012-0119", "CVE-2012-0120", "CVE-2012-0484", "CVE-2012-0485", "CVE-2012-0486", "CVE-2012-0487", "CVE-2012-0488", "CVE-2012-0489", "CVE-2012-0490", "CVE-2012-0491", "CVE-2012-0492", "CVE-2012-0493", "CVE-2012-0494", "CVE-2012-0495", "CVE-2012-0496");
  script_bugtraq_id(51488, 51493, 51502, 51503, 51504, 51505, 51506, 51507, 51508, 51509, 51510, 51511, 51512, 51513, 51514, 51515, 51516, 51517, 51518, 51519, 51520, 51521, 51522, 51523, 51524, 51525, 51526);
  script_osvdb_id(78368, 78369, 78370, 78371, 78372, 78373, 78374, 78375, 78376, 78377, 78378, 78379, 78380, 78381, 78382, 78383, 78384, 78385, 78386, 78387, 78388, 78389, 78390, 78391, 78392, 78393, 78394);

  script_name(english:"F5 Networks BIG-IP : Multiple MySQL vulnerabilities (K14410)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"For BIG-IP systems using the MySQL database, the following MySQL
vulnerabilities may allow local users to gain knowledge of sensitive
information, manipulate certain data, or cause a Denial of Service
(DoS):CVE-2011-2262

CVE-2012-0075

CVE-2012-0087

CVE-2012-0101

CVE-2012-0102

CVE-2012-0112

CVE-2012-0113

CVE-2012-0114

CVE-2012-0115

CVE-2012-0116

CVE-2012-0117

CVE-2012-0118

CVE-2012-0119

CVE-2012-0120

CVE-2012-0484

CVE-2012-0485

CVE-2012-0486

CVE-2012-0487

CVE-2012-0488

CVE-2012-0489

CVE-2012-0490

CVE-2012-0491

CVE-2012-0492

CVE-2012-0493

CVE-2012-0494

CVE-2012-0495

CVE-2012-0496

For Enterprise Manager systems, the following MySQL vulnerability may
also allow remote users to gain knowledge of sensitive information,
manipulate certain data, or cause a DoS :

CVE-2011-2262"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/#/article/K14410"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K14410."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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

sol = "K14410";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("10.1.0-10.2.4","11.0.0-11.2.1");
vmatrix["APM"]["unaffected"] = make_list("11.3.0-11.4.0");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("9.2.0-9.4.8","10.0.0-10.2.4","11.0.0-11.2.1");
vmatrix["ASM"]["unaffected"] = make_list("11.3.0-11.4.0");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("11.0.0-11.2.1");
vmatrix["AVR"]["unaffected"] = make_list("11.3.0-11.4.0");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("9.4.5-9.4.8","10.0.0-10.2.4","11.0.0-11.2.1");
vmatrix["PSM"]["unaffected"] = make_list("11.3.0-11.4.0");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("9.4.0-9.4.8","10.0.0-10.2.4","11.0.0-11.2.1");
vmatrix["WAM"]["unaffected"] = make_list("11.3.0");


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
