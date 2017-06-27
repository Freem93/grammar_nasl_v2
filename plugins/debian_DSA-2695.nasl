#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2695. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(66676);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/02/16 15:43:09 $");

  script_cve_id("CVE-2013-2837", "CVE-2013-2838", "CVE-2013-2839", "CVE-2013-2840", "CVE-2013-2841", "CVE-2013-2842", "CVE-2013-2843", "CVE-2013-2844", "CVE-2013-2845", "CVE-2013-2846", "CVE-2013-2847", "CVE-2013-2848", "CVE-2013-2849");
  script_bugtraq_id(60063, 60064, 60065, 60066, 60067, 60068, 60069, 60070, 60071, 60072, 60073, 60074, 60076);
  script_xref(name:"DSA", value:"2695");

  script_name(english:"Debian DSA-2695-1 : chromium-browser - several issues");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Chromium web
browser. Multiple use-after-free, out-of-bounds read, memory safety,
and cross-site scripting issues were discovered and corrected.

  - CVE-2013-2837
    Use-after-free vulnerability in the SVG implementation
    allows remote attackers to cause a denial of service or
    possibly have unspecified other impact via unknown
    vectors.

  - CVE-2013-2838
    Google V8, as used in Chromium before 27.0.1453.93,
    allows remote attackers to cause a denial of service
    (out-of-bounds read) via unspecified vectors.

  - CVE-2013-2839
    Chromium before 27.0.1453.93 does not properly perform a
    cast of an unspecified variable during handling of
    clipboard data, which allows remote attackers to cause a
    denial of service or possibly have other impact via
    unknown vectors.

  - CVE-2013-2840
    Use-after-free vulnerability in the media loader in
    Chromium before 27.0.1453.93 allows remote attackers to
    cause a denial of service or possibly have unspecified
    other impact via unknown vectors, a different
    vulnerability than CVE-2013-2846.

  - CVE-2013-2841
    Use-after-free vulnerability in Chromium before
    27.0.1453.93 allows remote attackers to cause a denial
    of service or possibly have unspecified other impact via
    vectors related to the handling of Pepper resources.

  - CVE-2013-2842
    Use-after-free vulnerability in Chromium before
    27.0.1453.93 allows remote attackers to cause a denial
    of service or possibly have unspecified other impact via
    vectors related to the handling of widgets.

  - CVE-2013-2843
    Use-after-free vulnerability in Chromium before
    27.0.1453.93 allows remote attackers to cause a denial
    of service or possibly have unspecified other impact via
    vectors related to the handling of speech data.

  - CVE-2013-2844
    Use-after-free vulnerability in the Cascading Style
    Sheets (CSS) implementation in Chromium before
    27.0.1453.93 allows remote attackers to cause a denial
    of service or possibly have unspecified other impact via
    vectors related to style resolution.

  - CVE-2013-2845
    The Web Audio implementation in Chromium before
    27.0.1453.93 allows remote attackers to cause a denial
    of service (memory corruption) or possibly have
    unspecified other impact via unknown vectors.

  - CVE-2013-2846
    Use-after-free vulnerability in the media loader in
    Chromium before 27.0.1453.93 allows remote attackers to
    cause a denial of service or possibly have unspecified
    other impact via unknown vectors, a different
    vulnerability than CVE-2013-2840.

  - CVE-2013-2847
    Race condition in the workers implementation in Chromium
    before 27.0.1453.93 allows remote attackers to cause a
    denial of service (use-after-free and application crash)
    or possibly have unspecified other impact via unknown
    vectors.

  - CVE-2013-2848
    The XSS Auditor in Chromium before 27.0.1453.93 might
    allow remote attackers to obtain sensitive information
    via unspecified vectors.

  - CVE-2013-2849
    Multiple cross-site scripting (XSS) vulnerabilities in
    Chromium before 27.0.1453.93 allow user-assisted remote
    attackers to inject arbitrary web script or HTML via
    vectors involving a (1) drag-and-drop or (2)
    copy-and-paste operation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2838"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2849"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2695"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the oldstable distribution (squeeze), the security support window
for Chromium has ended. Users of Chromium on oldstable are very highly
encouraged to upgrade to the current stable Debian release (wheezy).
Chromium security support for wheezy will last until the next stable
release (jessie), which is expected to happen sometime in 2015.

For the stable distribution (wheezy), these problems have been fixed
in version 27.0.1453.93-1~deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"chromium", reference:"27.0.1453.93-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser", reference:"27.0.1453.93-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser-dbg", reference:"27.0.1453.93-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser-inspector", reference:"27.0.1453.93-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser-l10n", reference:"27.0.1453.93-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-dbg", reference:"27.0.1453.93-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-inspector", reference:"27.0.1453.93-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-l10n", reference:"27.0.1453.93-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
