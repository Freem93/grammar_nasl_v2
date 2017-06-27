#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K16900.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(91368);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/04/07 15:07:04 $");

  script_cve_id("CVE-2014-9657", "CVE-2014-9658", "CVE-2014-9660", "CVE-2014-9661", "CVE-2014-9663", "CVE-2014-9664", "CVE-2014-9667", "CVE-2014-9669", "CVE-2014-9670", "CVE-2014-9671", "CVE-2014-9673", "CVE-2014-9674", "CVE-2014-9675");
  script_bugtraq_id(72986);
  script_osvdb_id(114332, 114333, 114354, 114619, 114621, 114961, 114962, 114964, 114965, 115073, 115075, 115098);

  script_name(english:"F5 Networks BIG-IP : Multiple FreeType vulnerabilities (K16900)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2014-9657 The tt_face_load_hdmx function in truetype/ttpload.c in
FreeType before 2.5.4 does not establish a minimum record size, which
allows remote attackers to cause a denial of service (out-of-bounds
read) or possibly have unspecified other impact via a crafted TrueType
font.

CVE-2014-9658 The tt_face_load_kern function in sfnt/ttkern.c in
FreeType before 2.5.4 enforces an incorrect minimum table length,
which allows remote attackers to cause a denial of service
(out-of-bounds read) or possibly have unspecified other impact via a
crafted TrueType font.

CVE-2014-9660 The _bdf_parse_glyphs function in bdf/bdflib.c in
FreeType before 2.5.4 does not properly handle a missing ENDCHAR
record, which allows remote attackers to cause a denial of service
(NULL pointer dereference) or possibly have unspecified other impact
via a crafted BDF font.

CVE-2014-9661 type42/t42parse.c in FreeType before 2.5.4 does not
consider that scanning can be incomplete without triggering an error,
which allows remote attackers to cause a denial of service
(use-after-free) or possibly have unspecified other impact via a
crafted Type42 font.

CVE-2014-9663 The tt_cmap4_validate function in sfnt/ttcmap.c in
FreeType before 2.5.4 validates a certain length field before that
field's value is completely calculated, which allows remote attackers
to cause a denial of service (out-of-bounds read) or possibly have
unspecified other impact via a crafted cmap SFNT table.

CVE-2014-9664 FreeType before 2.5.4 does not check for the end of the
data during certain parsing actions, which allows remote attackers to
cause a denial of service (out-of-bounds read) or possibly have
unspecified other impact via a crafted Type42 font, related to
type42/t42parse.c and type1/t1load.c.

CVE-2014-9667 sfnt/ttload.c in FreeType before 2.5.4 proceeds with
offset+length calculations without restricting the values, which
allows remote attackers to cause a denial of service (integer overflow
and out-of-bounds read) or possibly have unspecified other impact via
a crafted SFNT table.

CVE-2014-9669 Multiple integer overflows in sfnt/ttcmap.c in FreeType
before 2.5.4 allow remote attackers to cause a denial of service
(out-of-bounds read or memory corruption) or possibly have unspecified
other impact via a crafted cmap SFNT table.

CVE-2014-9670 Multiple integer signedness errors in the
pcf_get_encodings function in pcf/pcfread.c in FreeType before 2.5.4
allow remote attackers to cause a denial of service (integer overflow,
NULL pointer dereference, and application crash) via a crafted PCF
file that specifies negative values for the first column and first
row.

CVE-2014-9671 Off-by-one error in the pcf_get_properties function in
pcf/pcfread.c in FreeType before 2.5.4 allows remote attackers to
cause a denial of service (NULL pointer dereference and application
crash) via a crafted PCF file with a 0xffffffff size value that is
improperly incremented.

CVE-2014-9673 Integer signedness error in the Mac_Read_POST_Resource
function in base/ftobjs.c in FreeType before 2.5.4 allows remote
attackers to cause a denial of service (heap-based buffer overflow) or
possibly have unspecified other impact via a crafted Mac font.

CVE-2014-9674 The Mac_Read_POST_Resource function in base/ftobjs.c in
FreeType before 2.5.4 proceeds with adding to length values without
validating the original values, which allows remote attackers to cause
a denial of service (integer overflow and heap-based buffer overflow)
or possibly have unspecified other impact via a crafted Mac font.

CVE-2014-9675 bdf/bdflib.c in FreeType before 2.5.4 identifies
property names by only verifying that an initial substring is present,
which allows remote attackers to discover heap pointer values and
bypass the ASLR protection mechanism via a crafted BDF font."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/#/article/K16900"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K16900."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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

sol = "K16900";
vmatrix = make_array();

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("12.0.0","11.3.0-11.6.1");
vmatrix["AFM"]["unaffected"] = make_list("12.1.0");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("12.0.0","11.4.0-11.6.1");
vmatrix["AM"]["unaffected"] = make_list("12.1.0");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("12.0.0","11.0.0-11.6.1","10.1.0-10.2.4");
vmatrix["APM"]["unaffected"] = make_list("12.1.0");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("12.0.0","11.0.0-11.6.1","10.1.0-10.2.4");
vmatrix["ASM"]["unaffected"] = make_list("12.1.0");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("12.0.0","11.0.0-11.6.1");
vmatrix["AVR"]["unaffected"] = make_list("12.1.0");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("12.0.0","11.0.0-11.6.1","10.1.0-10.2.4");
vmatrix["LC"]["unaffected"] = make_list("12.1.0");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("12.0.0","11.0.0-11.6.1","10.0.0-10.2.4");
vmatrix["LTM"]["unaffected"] = make_list("12.1.0");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("12.0.0","11.3.0-11.6.1");
vmatrix["PEM"]["unaffected"] = make_list("12.1.0");


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
