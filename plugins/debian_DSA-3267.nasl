#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3267. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(83784);
  script_version("$Revision: 2.12 $");
  script_cvs_date("$Date: 2016/11/25 16:29:19 $");

  script_cve_id("CVE-2015-1251", "CVE-2015-1252", "CVE-2015-1253", "CVE-2015-1254", "CVE-2015-1255", "CVE-2015-1256", "CVE-2015-1257", "CVE-2015-1258", "CVE-2015-1259", "CVE-2015-1260", "CVE-2015-1261", "CVE-2015-1262", "CVE-2015-1263", "CVE-2015-1264", "CVE-2015-1265");
  script_bugtraq_id(74723, 74727);
  script_osvdb_id(120092, 122287, 122288, 122291, 122292, 122293, 122294, 122295, 122296, 122297, 122298, 122299, 122300, 122330, 122340, 122343, 122359, 122360, 122377, 122378, 122380, 122398, 122400, 122406);
  script_xref(name:"DSA", value:"3267");

  script_name(english:"Debian DSA-3267-1 : chromium-browser - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in the chromium web browser.

  - CVE-2015-1251
    SkyLined discovered a use-after-free issue in speech
    recognition.

  - CVE-2015-1252
    An out-of-bounds write issue was discovered that could
    be used to escape from the sandbox.

  - CVE-2015-1253
    A cross-origin bypass issue was discovered in the DOM
    parser.

  - CVE-2015-1254
    A cross-origin bypass issue was discovered in the DOM
    editing feature.

  - CVE-2015-1255
    Khalil Zhani discovered a use-after-free issue in
    WebAudio.

  - CVE-2015-1256
    Atte Kettunen discovered a use-after-free issue in the
    SVG implementation.

  - CVE-2015-1257
    miaubiz discovered an overflow issue in the SVG
    implementation.

  - CVE-2015-1258
    cloudfuzzer discovered an invalid size parameter used in
    the libvpx library.

  - CVE-2015-1259
    Atte Kettunen discovered an uninitialized memory issue
    in the pdfium library.

  - CVE-2015-1260
    Khalil Zhani discovered multiple use-after-free issues
    in chromium's interface to the WebRTC library.

  - CVE-2015-1261
    Juho Nurminen discovered a URL bar spoofing issue.

  - CVE-2015-1262
    miaubiz discovered the use of an uninitialized class
    member in font handling.

  - CVE-2015-1263
    Mike Ruddy discovered that downloading the spellcheck
    dictionary was not done over HTTPS.

  - CVE-2015-1264
    K0r3Ph1L discovered a cross-site scripting issue that
    could be triggered by bookmarking a site.

  - CVE-2015-1265
    The chrome 43 development team found and fixed various
    issues during internal auditing. Also multiple issues
    were fixed in the libv8 library, version 4.3.61.21."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1253"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1259"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1261"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1262"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1264"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3267"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (jessie), these problems have been fixed
in version 43.0.2357.65-1~deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/26");
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
if (deb_check(release:"8.0", prefix:"chromedriver", reference:"43.0.2357.65-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium", reference:"43.0.2357.65-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-dbg", reference:"43.0.2357.65-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-inspector", reference:"43.0.2357.65-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-l10n", reference:"43.0.2357.65-1~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
