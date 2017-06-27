#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K16715.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(84010);
  script_version("$Revision: 2.12 $");
  script_cvs_date("$Date: 2017/04/07 15:07:04 $");

  script_cve_id("CVE-2013-1960", "CVE-2013-1961", "CVE-2013-4231", "CVE-2013-4232", "CVE-2013-4243", "CVE-2013-4244");
  script_bugtraq_id(59607, 59609, 61695, 61849, 62019, 62082);
  script_osvdb_id(92986, 92987, 96203, 96204, 96205, 96206, 96207, 96649, 96783);

  script_name(english:"F5 Networks BIG-IP : Multiple LibTIFF vulnerabilities (K16715)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2013-1960 Heap-based buffer overflow in the t2p_process_jpeg_strip
function in tiff2pdf in libtiff 4.0.3 and earlier allows remote
attackers to cause a denial of service (crash) and possibly execute
arbitrary code via a crafted TIFF image file.

CVE-2013-1961 Stack-based buffer overflow in the t2p_write_pdf_page
function in tiff2pdf in libtiff before 4.0.3 allows remote attackers
to cause a denial of service (application crash) via a crafted image
length and resolution in a TIFF image file.

CVE-2013-4231 Multiple buffer overflows in libtiff before 4.0.3 allow
remote attackers to cause a denial of service (out-of-bounds write)
via a crafted (1) extension block in a GIF image or (2) GIF raster
image to tools/gif2tiff.c or (3) a long filename for a TIFF image to
tools/rgb2ycbcr.c.

CVE-2013-4232 Use-after-free vulnerability in the
t2p_readwrite_pdf_image function in tools/tiff2pdf.c in libtiff 4.0.3
allows remote attackers to cause a denial of service (crash) or
possible execute arbitrary code via a crafted TIFF image.

CVE-2013-4243 Heap-based buffer overflow in the readgifimage function
in the gif2tiff tool in libtiff 4.0.3 and earlier allows remote
attackers to cause a denial of service (crash) and possibly execute
arbitrary code via a crafted height and width values in a GIF image.

CVE-2013-4244 The LZW decompressor in the gif2tiff tool in libtiff
4.0.3 and earlier allows context-dependent attackers to cause a denial
of service (out-of-bounds write and crash) or possibly execute
arbitrary code via a crafted GIF image."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/#/article/K16715"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K16715."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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

sol = "K16715";
vmatrix = make_array();

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("11.3.0-12.0.0");
vmatrix["AFM"]["unaffected"] = make_list("12.1.0","11.6.1HF1","11.5.4HF2");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("11.4.0-12.0.0");
vmatrix["AM"]["unaffected"] = make_list("12.1.0","11.6.1HF1","11.5.4HF2");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("11.2.0-12.0.0");
vmatrix["APM"]["unaffected"] = make_list("12.1.0","11.6.1HF1","11.5.4HF2","11.0.0-11.1.0","10.1.0-10.2.4");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("11.2.0-12.0.0");
vmatrix["ASM"]["unaffected"] = make_list("12.1.0","11.6.1HF1","11.5.4HF2","11.0.0-11.1.0","10.0.0-10.2.4");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("11.2.0-12.0.0");
vmatrix["AVR"]["unaffected"] = make_list("12.1.0","11.6.1HF1","11.5.4HF2","11.0.0-11.1.0");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.2.0-11.6.0");
vmatrix["GTM"]["unaffected"] = make_list("11.6.1HF1","11.5.4HF2","11.0.0-11.1.0","10.0.0-10.2.4");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("11.2.0-12.0.0");
vmatrix["LC"]["unaffected"] = make_list("12.1.0","11.6.1HF1","11.5.4HF2","11.0.0-11.1.0","10.0.0-10.2.4");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("11.2.0-12.0.0");
vmatrix["LTM"]["unaffected"] = make_list("12.1.0","11.6.1HF1","11.5.4HF2","11.0.0-11.1.0","10.0.0-10.2.4");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("11.3.0-12.0.0");
vmatrix["PEM"]["unaffected"] = make_list("12.1.0","11.6.1HF1","11.5.4HF2");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("11.2.0-11.4.1");
vmatrix["PSM"]["unaffected"] = make_list("11.0.0-11.1.0","10.0.0-10.2.4");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("11.2.0-11.3.0");
vmatrix["WAM"]["unaffected"] = make_list("11.0.0-11.1.0","10.0.0-10.2.4");

# WOM
vmatrix["WOM"] = make_array();
vmatrix["WOM"]["affected"  ] = make_list("11.2.0-11.3.0");
vmatrix["WOM"]["unaffected"] = make_list("11.0.0-11.1.0","10.0.0-10.2.4");


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
