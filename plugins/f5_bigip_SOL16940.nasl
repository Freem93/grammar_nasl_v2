#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K16940.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(84627);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2017/04/07 15:07:04 $");

  script_cve_id("CVE-2014-6423", "CVE-2014-6425", "CVE-2014-6428", "CVE-2014-6429", "CVE-2014-6430", "CVE-2014-6431", "CVE-2014-6432");
  script_bugtraq_id(69853, 69857, 69858, 69859, 69860, 69865, 69866);
  script_osvdb_id(111600, 111601, 111605, 111633, 111634, 111635, 111636);

  script_name(english:"F5 Networks BIG-IP : Multiple Wireshark vulnerabilities (K16940)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2014-6423 The tvb_raw_text_add function in
epan/dissectors/packet-megaco.c in the MEGACO dissector in Wireshark
1.10.x before 1.10.10 and 1.12.x before 1.12.1 allows remote attackers
to cause a denial of service (infinite loop) via an empty line./

CVE-2014-6425 The (1) get_quoted_string and (2) get_unquoted_string
functions in epan/dissectors/packet-cups.c in the CUPS dissector in
Wireshark 1.12.x before 1.12.1 allow remote attackers to cause a
denial of service (buffer over-read and application crash) via a CUPS
packet that lacks a trailing '\0' character.

CVE-2014-6428 The dissect_spdu function in
epan/dissectors/packet-ses.c in the SES dissector in Wireshark 1.10.x
before 1.10.10 and 1.12.x before 1.12.1 does not initialize a certain
ID value, which allows remote attackers to cause a denial of service
(application crash) via a crafted packet.

CVE-2014-6429 The SnifferDecompress function in wiretap/ngsniffer.c in
the DOS Sniffer file parser in Wireshark 1.10.x before 1.10.10 and
1.12.x before 1.12.1 does not properly handle empty input data, which
allows remote attackers to cause a denial of service (application
crash) via a crafted file.

CVE-2014-6430 The SnifferDecompress function in wiretap/ngsniffer.c in
the DOS Sniffer file parser in Wireshark 1.10.x before 1.10.10 and
1.12.x before 1.12.1 does not validate bitmask data, which allows
remote attackers to cause a denial of service (application crash) via
a crafted file.

CVE-2014-6431 Buffer overflow in the SnifferDecompress function in
wiretap/ngsniffer.c in the DOS Sniffer file parser in Wireshark 1.10.x
before 1.10.10 and 1.12.x before 1.12.1 allows remote attackers to
cause a denial of service (application crash) via a crafted file that
triggers writes of uncompressed bytes beyond the end of the output
buffer.

CVE-2014-6432 The SnifferDecompress function in wiretap/ngsniffer.c in
the DOS Sniffer file parser in Wireshark 1.10.x before 1.10.10 and
1.12.x before 1.12.1 does not prevent data overwrites during copy
operations, which allows remote attackers to cause a denial of service
(application crash) via a crafted file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/#/article/K16940"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K16940."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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

sol = "K16940";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("11.3.0-11.6.1");
vmatrix["AFM"]["unaffected"] = make_list("12.0.0-12.1.1","11.6.1HF1","11.5.4HF2");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("11.4.0-11.6.1");
vmatrix["AM"]["unaffected"] = make_list("12.0.0-12.1.1","11.6.1HF1","11.5.4HF2");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("11.3.0-11.6.1");
vmatrix["APM"]["unaffected"] = make_list("12.0.0-12.1.1","11.6.1HF1","11.5.4HF2","11.0.0-11.2.1","10.1.0-10.2.4");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("11.3.0-11.6.1");
vmatrix["ASM"]["unaffected"] = make_list("12.0.0-12.1.1","11.6.1HF1","11.5.4HF2","11.0.0-11.2.1","10.1.0-10.2.4");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("11.3.0-11.6.1");
vmatrix["AVR"]["unaffected"] = make_list("12.0.0-12.1.1","11.6.1HF1","11.5.4HF2","11.0.0-11.2.1");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.3.0-11.6.1");
vmatrix["GTM"]["unaffected"] = make_list("11.6.1HF1","11.5.4HF2","11.0.0-11.2.1","10.1.0-10.2.4");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("11.3.0-11.6.0");
vmatrix["LC"]["unaffected"] = make_list("12.0.0-12.1.1","11.6.1HF1","11.5.4HF2","11.0.0-11.2.1","10.1.0-10.2.4");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("11.3.0-11.6.1");
vmatrix["LTM"]["unaffected"] = make_list("12.0.0-12.1.1","11.6.1HF1","11.5.4HF2","11.0.0-11.2.1","10.1.0-10.2.4");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("11.3.0-11.6.1");
vmatrix["PEM"]["unaffected"] = make_list("12.0.0-12.1.1","11.6.1HF1");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("11.3.0-11.4.1");
vmatrix["PSM"]["unaffected"] = make_list("11.0.0-11.2.1","10.1.0-10.2.4");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("11.3.0");
vmatrix["WAM"]["unaffected"] = make_list("11.0.0-11.2.1","10.1.0-10.2.4");

# WOM
vmatrix["WOM"] = make_array();
vmatrix["WOM"]["affected"  ] = make_list("11.3.0");
vmatrix["WOM"]["unaffected"] = make_list("11.0.0-11.2.1","10.1.0-10.2.4");


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
