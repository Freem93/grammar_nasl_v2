#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2706. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66852);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:43 $");

  script_cve_id("CVE-2013-2855", "CVE-2013-2856", "CVE-2013-2857", "CVE-2013-2858", "CVE-2013-2859", "CVE-2013-2860", "CVE-2013-2861", "CVE-2013-2862", "CVE-2013-2863", "CVE-2013-2865");
  script_bugtraq_id(60395, 60396, 60397, 60398, 60399, 60400, 60401, 60403, 60404, 60405);
  script_xref(name:"DSA", value:"2706");

  script_name(english:"Debian DSA-2706-1 : chromium-browser - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Chromium web
browser.

  - CVE-2013-2855
    The Developer Tools API in Chromium before 27.0.1453.110
    allows remote attackers to cause a denial of service
    (memory corruption) or possibly have unspecified other
    impact via unknown vectors.

  - CVE-2013-2856
    Use-after-free vulnerability in Chromium before
    27.0.1453.110 allows remote attackers to cause a denial
    of service or possibly have unspecified other impact via
    vectors related to the handling of input.

  - CVE-2013-2857
    Use-after-free vulnerability in Chromium before
    27.0.1453.110 allows remote attackers to cause a denial
    of service or possibly have unspecified other impact via
    vectors related to the handling of images.

  - CVE-2013-2858
    Use-after-free vulnerability in the HTML5 Audio
    implementation in Chromium before 27.0.1453.110 allows
    remote attackers to cause a denial of service or
    possibly have unspecified other impact via unknown
    vectors.

  - CVE-2013-2859
    Chromium before 27.0.1453.110 allows remote attackers to
    bypass the Same Origin Policy and trigger namespace
    pollution via unspecified vectors.

  - CVE-2013-2860
    Use-after-free vulnerability in Chromium before
    27.0.1453.110 allows remote attackers to cause a denial
    of service or possibly have unspecified other impact via
    vectors involving access to a database API by a worker
    process.

  - CVE-2013-2861
    Use-after-free vulnerability in the SVG implementation
    in Chromium before 27.0.1453.110 allows remote attackers
    to cause a denial of service or possibly have
    unspecified other impact via unknown vectors.

  - CVE-2013-2862
    Skia, as used in Chromium before 27.0.1453.110, does not
    properly handle GPU acceleration, which allows remote
    attackers to cause a denial of service (memory
    corruption) or possibly have unspecified other impact
    via unknown vectors.

  - CVE-2013-2863
    Chromium before 27.0.1453.110 does not properly handle
    SSL sockets, which allows remote attackers to execute
    arbitrary code or cause a denial of service (memory
    corruption) via unspecified vectors.

  - CVE-2013-2865
    Multiple unspecified vulnerabilities in Chromium before
    27.0.1453.110 allow attackers to cause a denial of
    service or possibly have other impact via unknown
    vectors."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2856"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2859"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2861"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2862"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2863"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2865"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2706"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (wheezy), these problems have been fixed
in version 27.0.1453.110-1~deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"chromium", reference:"27.0.1453.110-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser", reference:"27.0.1453.110-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser-dbg", reference:"27.0.1453.110-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser-inspector", reference:"27.0.1453.110-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser-l10n", reference:"27.0.1453.110-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-dbg", reference:"27.0.1453.110-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-inspector", reference:"27.0.1453.110-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-l10n", reference:"27.0.1453.110-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
