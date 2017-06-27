#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2785. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(70636);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/02/16 15:43:10 $");

  script_cve_id("CVE-2013-2906", "CVE-2013-2907", "CVE-2013-2908", "CVE-2013-2909", "CVE-2013-2910", "CVE-2013-2911", "CVE-2013-2912", "CVE-2013-2913", "CVE-2013-2915", "CVE-2013-2916", "CVE-2013-2917", "CVE-2013-2918", "CVE-2013-2919", "CVE-2013-2920", "CVE-2013-2921", "CVE-2013-2922", "CVE-2013-2923", "CVE-2013-2924", "CVE-2013-2925", "CVE-2013-2926", "CVE-2013-2927", "CVE-2013-2928");
  script_bugtraq_id(62752, 62968, 63024, 63025, 63026, 63028);
  script_osvdb_id(96406, 96950, 96951, 96952, 96953, 96954, 97966, 97967, 97968, 97970, 97971, 97972, 97973, 97975, 97976, 97977, 97978, 97979, 97980, 97981, 97982, 97992, 97993, 97994, 97995, 97996, 97997, 97998, 97999, 98000, 98001, 98002, 98003, 98004, 98005, 98006, 98007, 98008, 98009, 98010, 98011, 98012, 98013, 98014, 98024, 98591, 98592, 98593, 98594, 98595);
  script_xref(name:"DSA", value:"2785");

  script_name(english:"Debian DSA-2785-1 : chromium-browser - several vulnerabilities");
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

  - CVE-2013-2906
    Atte Kettunen of OUSPG discovered race conditions in Web
    Audio.

  - CVE-2013-2907
    Boris Zbarsky discovered an out-of-bounds read in
    window.prototype.

  - CVE-2013-2908
    Chamal de Silva discovered an address bar spoofing
    issue.

  - CVE-2013-2909
    Atte Kuttenen of OUSPG discovered a use-after-free issue
    in inline-block.

  - CVE-2013-2910
    Byoungyoung Lee of the Georgia Tech Information Security
    Center discovered a use-after-free issue in Web Audio.

  - CVE-2013-2911
    Atte Kettunen of OUSPG discovered a use-after-free in
    Blink's XSLT handling.

  - CVE-2013-2912
    Chamal de Silva and 41.w4r10r(at)garage4hackers.com
    discovered a use-after-free issue in the Pepper Plug-in
    API.

  - CVE-2013-2913
    cloudfuzzer discovered a use-after-free issue in Blink's
    XML document parsing.

  - CVE-2013-2915
    Wander Groeneveld discovered an address bar spoofing
    issue.

  - CVE-2013-2916
    Masato Kinugawa discovered an address bar spoofing
    issue.

  - CVE-2013-2917
    Byoungyoung Lee and Tielei Wang discovered an
    out-of-bounds read issue in Web Audio.

  - CVE-2013-2918
    Byoungyoung Lee discoverd an out-of-bounds read in
    Blink's DOM implementation.

  - CVE-2013-2919
    Adam Haile of Concrete Data discovered a memory
    corruption issue in the V8 JavaScript library.

  - CVE-2013-2920
    Atte Kuttunen of OUSPG discovered an out-of-bounds read
    in URL host resolving.

  - CVE-2013-2921
    Byoungyoung Lee and Tielei Wang discovered a
    use-after-free issue in resource loading.

  - CVE-2013-2922
    Jon Butler discovered a use-after-free issue in Blink's
    HTML template element implementation.

  - CVE-2013-2924
    A use-after-free issue was discovered in the
    International Components for Unicode (ICU) library. 

  - CVE-2013-2925
    Atte Kettunen of OUSPG discover a use-after-free issue
    in Blink's XML HTTP request implementation.

  - CVE-2013-2926
    cloudfuzzer discovered a use-after-free issue in the
    list indenting implementation.

  - CVE-2013-2927
    cloudfuzzer discovered a use-after-free issue in the
    HTML form submission implementation. 

  - CVE-2013-2923 and CVE-2013-2928
    The chrome 30 development team found various issues from
    internal fuzzing, audits, and other studies."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2909"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2915"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2916"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2918"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2921"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2927"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2785"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (wheezy), these problems have been fixed
in version 30.0.1599.101-1~deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/27");
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
if (deb_check(release:"7.0", prefix:"chromium", reference:"30.0.1599.101-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser", reference:"30.0.1599.101-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser-dbg", reference:"30.0.1599.101-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser-inspector", reference:"30.0.1599.101-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser-l10n", reference:"30.0.1599.101-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-dbg", reference:"30.0.1599.101-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-inspector", reference:"30.0.1599.101-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-l10n", reference:"30.0.1599.101-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
