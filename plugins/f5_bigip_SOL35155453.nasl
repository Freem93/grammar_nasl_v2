#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K35155453.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(94647);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/03/14 16:13:00 $");

  script_cve_id("CVE-2014-8127", "CVE-2014-8129", "CVE-2014-8130", "CVE-2014-9655", "CVE-2015-8665", "CVE-2015-8683", "CVE-2015-8781", "CVE-2015-8782", "CVE-2015-8783");
  script_bugtraq_id(72323, 72352, 72353, 73441);
  script_osvdb_id(116688, 116700, 116706, 116711, 117615, 117750, 117835, 117836, 132240, 132276, 133559, 133560, 133561, 133569);

  script_name(english:"F5 Networks BIG-IP : Multiple LibTIFF vulnerabilities (K35155453)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2015-8683 The putcontig8bitCIELab function in tif_getimage.c in
LibTIFF 4.0.6 allows remote attackers to cause a denial of service
(out-of-bounds read) via a packed TIFF image.

CVE-2015-8665 tif_getimage.c in LibTIFF 4.0.6 allows remote attackers
to cause a denial of service (out-of-bounds read) via the
SamplesPerPixel tag in a TIFF image.

CVE-2014-8129 ** RESERVED ** This candidate has been reserved by an
organization or individual that will use it when announcing a new
security problem. When the candidate has been publicized, the details
for this candidate will be provided.

CVE-2014-8130 ** RESERVED ** This candidate has been reserved by an
organization or individual that will use it when announcing a new
security problem. When the candidate has been publicized, the details
for this candidate will be provided.

CVE-2014-8127 ** RESERVED ** This candidate has been reserved by an
organization or individual that will use it when announcing a new
security problem. When the candidate has been publicized, the details
for this candidate will be provided.

CVE-2014-9655 The (1) putcontig8bitYCbCr21tile function in
tif_getimage.c or (2) NeXTDecode function in tif_next.c in LibTIFF
allows remote attackers to cause a denial of service (uninitialized
memory access) via a crafted TIFF image, as demonstrated by
libtiff-cvs-1.tif and libtiff-cvs-2.tif.

CVE-2015-8781 tif_luv.c in libtiff allows attackers to cause a denial
of service (out-of-bounds write) via an invalid number of samples per
pixel in a LogL compressed TIFF image, a different vulnerability than
CVE-2015-8782.

CVE-2015-8782 tif_luv.c in libtiff allows attackers to cause a denial
of service (out-of-bounds writes) via a crafted TIFF image, a
different vulnerability than CVE-2015-8781.

CVE-2015-8783 tif_luv.c in libtiff allows attackers to cause a denial
of service (out-of-bounds reads) via a crafted TIFF image."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/#/article/K35155453"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K35155453."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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

sol = "K35155453";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("12.0.0-12.1.2","11.4.0-11.6.1");
vmatrix["AM"]["unaffected"] = make_list("13.0.0");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("11.2.1");
vmatrix["WAM"]["unaffected"] = make_list("10.2.1-10.2.4");


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
  else audit(AUDIT_HOST_NOT, "running any of the affected modules AM / WAM");
}
