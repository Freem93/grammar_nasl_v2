#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2559. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62599);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2012-2812", "CVE-2012-2813", "CVE-2012-2814", "CVE-2012-2836", "CVE-2012-2837", "CVE-2012-2840", "CVE-2012-2841");
  script_bugtraq_id(54437);
  script_osvdb_id(83753, 83754, 83755, 83757, 83758, 83759);
  script_xref(name:"DSA", value:"2559");

  script_name(english:"Debian DSA-2559-1 : libexif - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were found in libexif, a library used to parse
EXIF meta-data on camera files.

  - CVE-2012-2812 :
    A heap-based out-of-bounds array read in the
    exif_entry_get_value function allows remote attackers to
    cause a denial of service or possibly obtain potentially
    sensitive information from process memory via an image
    with crafted EXIF tags.

  - CVE-2012-2813 :
    A heap-based out-of-bounds array read in the
    exif_convert_utf16_to_utf8 function allows remote
    attackers to cause a denial of service or possibly
    obtain potentially sensitive information from process
    memory via an image with crafted EXIF tags.

  - CVE-2012-2814 :
    A buffer overflow in the exif_entry_format_value
    function allows remote attackers to cause a denial of
    service or possibly execute arbitrary code via an image
    with crafted EXIF tags.

  - CVE-2012-2836 :
    A heap-based out-of-bounds array read in the
    exif_data_load_data function allows remote attackers to
    cause a denial of service or possibly obtain potentially
    sensitive information from process memory via an image
    with crafted EXIF tags.

  - CVE-2012-2837 :
    A divide-by-zero error in the
    mnote_olympus_entry_get_value function while formatting
    EXIF maker note tags allows remote attackers to cause a
    denial of service via an image with crafted EXIF tags.

  - CVE-2012-2840 :
    An off-by-one error in the exif_convert_utf16_to_utf8
    function allows remote attackers to cause a denial of
    service or possibly execute arbitrary code via an image
    with crafted EXIF tags.

  - CVE-2012-2841 :
    An integer underflow in the exif_entry_get_value
    function can cause a heap overflow and potentially
    arbitrary code execution while formatting an EXIF tag,
    if the function is called with a buffer size parameter
    equal to zero or one."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=681454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-2812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-2813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-2814"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-2836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-2837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-2840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-2841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/libexif"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2559"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libexif packages.

For the stable distribution (squeeze), these problems have been fixed
in version 0.6.19-1+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libexif");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"6.0", prefix:"libexif-dev", reference:"0.6.19-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libexif12", reference:"0.6.19-1+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
