#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3376. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86486);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/11/17 18:50:40 $");

  script_cve_id("CVE-2015-1303", "CVE-2015-1304", "CVE-2015-6755", "CVE-2015-6756", "CVE-2015-6757", "CVE-2015-6758", "CVE-2015-6759", "CVE-2015-6760", "CVE-2015-6761", "CVE-2015-6762", "CVE-2015-6763");
  script_xref(name:"DSA", value:"3376");

  script_name(english:"Debian DSA-3376-1 : chromium-browser - security update");
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

  - CVE-2015-1303
    Mariusz Mlynski discovered a way to bypass the Same
    Origin Policy in the DOM implementation.

  - CVE-2015-1304
    Mariusz Mlynski discovered a way to bypass the Same
    Origin Policy in the v8 JavaScript library.

  - CVE-2015-6755
    Mariusz Mlynski discovered a way to bypass the Same
    Origin Policy in blink/webkit.

  - CVE-2015-6756
    A use-after-free issue was found in the pdfium library.

  - CVE-2015-6757
    Collin Payne found a use-after-free issue in the
    ServiceWorker implementation.

  - CVE-2015-6758
    Atte Kettunen found an issue in the pdfium library.

  - CVE-2015-6759
    Muneaki Nishimura discovered an information leak.

  - CVE-2015-6760
    Ronald Crane discovered a logic error in the ANGLE
    library involving lost device events.

  - CVE-2015-6761
    Aki Helin and Khalil Zhani discovered a memory
    corruption issue in the ffmpeg library.

  - CVE-2015-6762
    Muneaki Nishimura discovered a way to bypass the Same
    Origin Policy in the CSS implementation.

  - CVE-2015-6763
    The chrome 46 development team found and fixed various
    issues during internal auditing. Also multiple issues
    were fixed in the v8 JavaScript library, version
    4.6.85.23."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6756"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6757"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6759"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-6763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3376"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (jessie), these problems have been fixed
in version 46.0.2490.71-1~deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"chromedriver", reference:"46.0.2490.71-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium", reference:"46.0.2490.71-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-dbg", reference:"46.0.2490.71-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-inspector", reference:"46.0.2490.71-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-l10n", reference:"46.0.2490.71-1~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
