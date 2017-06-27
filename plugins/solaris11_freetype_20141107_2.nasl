#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80616);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2012-1126", "CVE-2012-1127", "CVE-2012-1128", "CVE-2012-1129", "CVE-2012-1130", "CVE-2012-1131", "CVE-2012-1132", "CVE-2012-1133", "CVE-2012-1134", "CVE-2012-1135", "CVE-2012-1136", "CVE-2012-1137", "CVE-2012-1138", "CVE-2012-1139", "CVE-2012-1140", "CVE-2012-1141", "CVE-2012-1142", "CVE-2012-1143", "CVE-2012-1144");

  script_name(english:"Oracle Solaris Third-Party Patch Update : freetype (multiple_denial_of_service_dos1)");
  script_summary(english:"Check for the 'entire' version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch for third-party
software."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Solaris system is missing necessary patches to address
security updates :

  - FreeType before 2.4.9, as used in Mozilla Firefox Mobile
    before 10.0.4 and other products, allows remote
    attackers to cause a denial of service (invalid heap
    read operation and memory corruption) or possibly
    execute arbitrary code via crafted property data in a
    BDF font. (CVE-2012-1126)

  - FreeType before 2.4.9, as used in Mozilla Firefox Mobile
    before 10.0.4 and other products, allows remote
    attackers to cause a denial of service (invalid heap
    read operation and memory corruption) or possibly
    execute arbitrary code via crafted glyph or bitmap data
    in a BDF font. (CVE-2012-1127)

  - FreeType before 2.4.9, as used in Mozilla Firefox Mobile
    before 10.0.4 and other products, allows remote
    attackers to cause a denial of service (NULL pointer
    dereference and memory corruption) or possibly execute
    arbitrary code via a crafted TrueType font.
    (CVE-2012-1128)

  - FreeType before 2.4.9, as used in Mozilla Firefox Mobile
    before 10.0.4 and other products, allows remote
    attackers to cause a denial of service (invalid heap
    read operation and memory corruption) or possibly
    execute arbitrary code via a crafted SFNT string in a
    Type 42 font. (CVE-2012-1129)

  - FreeType before 2.4.9, as used in Mozilla Firefox Mobile
    before 10.0.4 and other products, allows remote
    attackers to cause a denial of service (invalid heap
    read operation and memory corruption) or possibly
    execute arbitrary code via crafted property data in a
    PCF font. (CVE-2012-1130)

  - FreeType before 2.4.9, as used in Mozilla Firefox Mobile
    before 10.0.4 and other products, on 64-bit platforms
    allows remote attackers to cause a denial of service
    (invalid heap read operation and memory corruption) or
    possibly execute arbitrary code via vectors related to
    the cell table of a font. (CVE-2012-1131)

  - FreeType before 2.4.9, as used in Mozilla Firefox Mobile
    before 10.0.4 and other products, allows remote
    attackers to cause a denial of service (invalid heap
    read operation and memory corruption) or possibly
    execute arbitrary code via crafted dictionary data in a
    Type 1 font. (CVE-2012-1132)

  - FreeType before 2.4.9, as used in Mozilla Firefox Mobile
    before 10.0.4 and other products, allows remote
    attackers to cause a denial of service (invalid heap
    write operation and memory corruption) or possibly
    execute arbitrary code via crafted glyph or bitmap data
    in a BDF font. (CVE-2012-1133)

  - FreeType before 2.4.9, as used in Mozilla Firefox Mobile
    before 10.0.4 and other products, allows remote
    attackers to cause a denial of service (invalid heap
    write operation and memory corruption) or possibly
    execute arbitrary code via crafted private-dictionary
    data in a Type 1 font. (CVE-2012-1134)

  - FreeType before 2.4.9, as used in Mozilla Firefox Mobile
    before 10.0.4 and other products, allows remote
    attackers to cause a denial of service (invalid heap
    read operation and memory corruption) or possibly
    execute arbitrary code via vectors involving the NPUSHB
    and NPUSHW instructions in a TrueType font.
    (CVE-2012-1135)

  - FreeType before 2.4.9, as used in Mozilla Firefox Mobile
    before 10.0.4 and other products, allows remote
    attackers to cause a denial of service (invalid heap
    write operation and memory corruption) or possibly
    execute arbitrary code via crafted glyph or bitmap data
    in a BDF font that lacks an ENCODING field.
    (CVE-2012-1136)

  - FreeType before 2.4.9, as used in Mozilla Firefox Mobile
    before 10.0.4 and other products, allows remote
    attackers to cause a denial of service (invalid heap
    read operation and memory corruption) or possibly
    execute arbitrary code via a crafted header in a BDF
    font. (CVE-2012-1137)

  - FreeType before 2.4.9, as used in Mozilla Firefox Mobile
    before 10.0.4 and other products, allows remote
    attackers to cause a denial of service (invalid heap
    read operation and memory corruption) or possibly
    execute arbitrary code via vectors involving the MIRP
    instruction in a TrueType font. (CVE-2012-1138)

  - Array index error in FreeType before 2.4.9, as used in
    Mozilla Firefox Mobile before 10.0.4 and other products,
    allows remote attackers to cause a denial of service
    (invalid stack read operation and memory corruption) or
    possibly execute arbitrary code via crafted glyph data
    in a BDF font. (CVE-2012-1139)

  - FreeType before 2.4.9, as used in Mozilla Firefox Mobile
    before 10.0.4 and other products, allows remote
    attackers to cause a denial of service (invalid heap
    read operation and memory corruption) or possibly
    execute arbitrary code via a crafted PostScript font
    object. (CVE-2012-1140)

  - FreeType before 2.4.9, as used in Mozilla Firefox Mobile
    before 10.0.4 and other products, allows remote
    attackers to cause a denial of service (invalid heap
    read operation and memory corruption) or possibly
    execute arbitrary code via a crafted ASCII string in a
    BDF font. (CVE-2012-1141)

  - FreeType before 2.4.9, as used in Mozilla Firefox Mobile
    before 10.0.4 and other products, allows remote
    attackers to cause a denial of service (invalid heap
    write operation and memory corruption) or possibly
    execute arbitrary code via crafted glyph-outline data in
    a font. (CVE-2012-1142)

  - FreeType before 2.4.9, as used in Mozilla Firefox Mobile
    before 10.0.4 and other products, allows remote
    attackers to cause a denial of service (divide-by-zero
    error) via a crafted font. (CVE-2012-1143)

  - FreeType before 2.4.9, as used in Mozilla Firefox Mobile
    before 10.0.4 and other products, allows remote
    attackers to cause a denial of service (invalid heap
    write operation and memory corruption) or possibly
    execute arbitrary code via a crafted TrueType font.
    (CVE-2012-1144)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_denial_of_service_dos1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?911efc66"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11/11 SRU 8.5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:freetype");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris11/release", "Host/Solaris11/pkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Solaris11/release");
if (isnull(release)) audit(AUDIT_OS_NOT, "Solaris11");
pkg_list = solaris_pkg_list_leaves();
if (isnull (pkg_list)) audit(AUDIT_PACKAGE_LIST_MISSING, "Solaris pkg-list packages");

if (empty_or_null(egrep(string:pkg_list, pattern:"^freetype-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "freetype");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.0.8.0.5.0", sru:"SRU 8.5") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : freetype\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "freetype");
