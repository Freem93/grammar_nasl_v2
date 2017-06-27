#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3415. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(87289);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2015-1302", "CVE-2015-6764", "CVE-2015-6765", "CVE-2015-6766", "CVE-2015-6767", "CVE-2015-6768", "CVE-2015-6769", "CVE-2015-6770", "CVE-2015-6771", "CVE-2015-6772", "CVE-2015-6773", "CVE-2015-6774", "CVE-2015-6775", "CVE-2015-6776", "CVE-2015-6777", "CVE-2015-6778", "CVE-2015-6779", "CVE-2015-6780", "CVE-2015-6781", "CVE-2015-6782", "CVE-2015-6784", "CVE-2015-6785", "CVE-2015-6786");
  script_osvdb_id(120997, 129198, 130068, 130244, 130971, 130972, 130973, 130974, 130975, 130976, 130977, 130978, 130979, 130980, 130981, 130982, 130983, 130984, 130985, 130986, 130988, 130989, 130990);
  script_xref(name:"DSA", value:"3415");

  script_name(english:"Debian DSA-3415-1 : chromium-browser - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the chromium web
browser.

  - CVE-2015-1302
    Rub Wu discovered an information leak in the pdfium
    library.

  - CVE-2015-6764
    Guang Gong discovered an out-of-bounds read issue in the
    v8 JavaScript library.

  - CVE-2015-6765
    A use-after-free issue was discovered in AppCache.

  - CVE-2015-6766
    A use-after-free issue was discovered in AppCache.

  - CVE-2015-6767
    A use-after-free issue was discovered in AppCache.

  - CVE-2015-6768
    Mariusz Mlynski discovered a way to bypass the Same
    Origin Policy.

  - CVE-2015-6769
    Mariusz Mlynski discovered a way to bypass the Same
    Origin Policy.

  - CVE-2015-6770
    Mariusz Mlynski discovered a way to bypass the Same
    Origin Policy.

  - CVE-2015-6771
    An out-of-bounds read issue was discovered in the v8
    JavaScript library.

  - CVE-2015-6772
    Mariusz Mlynski discovered a way to bypass the Same
    Origin Policy.

  - CVE-2015-6773
    cloudfuzzer discovered an out-of-bounds read issue in
    the skia library.

  - CVE-2015-6774
    A use-after-free issue was found in extensions binding.

  - CVE-2015-6775
    Atte Kettunen discovered a type confusion issue in the
    pdfium library.

  - CVE-2015-6776
    Hanno Bock dicovered an out-of-bounds access issue in
    the openjpeg library, which is used by pdfium.

  - CVE-2015-6777
    Long Liu found a use-after-free issue.

  - CVE-2015-6778
    Karl Skomski found an out-of-bounds read issue in the
    pdfium library.

  - CVE-2015-6779
    Til Jasper Ullrich discovered that the pdfium library
    does not sanitize 'chrome:' URLs.

  - CVE-2015-6780
    Khalil Zhani discovered a use-after-free issue.

  - CVE-2015-6781
    miaubiz discovered an integer overflow issue in the
    sfntly library.

  - CVE-2015-6782
    Luan Herrera discovered a URL spoofing issue.

  - CVE-2015-6784
    Inti De Ceukelaire discovered a way to inject HTML into
    serialized web pages.

  - CVE-2015-6785
    Michael Ficarra discovered a way to bypass the Content
    Security Policy.

  - CVE-2015-6786
    Michael Ficarra discovered another way to bypass the
    Content Security Policy."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1302"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6764"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6765"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6781"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3415"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (jessie), these problems have been fixed
in version 47.0.2526.73-1~deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"chromedriver", reference:"47.0.2526.73-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium", reference:"47.0.2526.73-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-dbg", reference:"47.0.2526.73-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-inspector", reference:"47.0.2526.73-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-l10n", reference:"47.0.2526.73-1~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
