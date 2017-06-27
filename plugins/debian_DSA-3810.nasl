#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3810. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(97783);
  script_version("$Revision: 3.7 $");
  script_cvs_date("$Date: 2017/05/01 13:40:21 $");

  script_cve_id("CVE-2017-5029", "CVE-2017-5030", "CVE-2017-5031", "CVE-2017-5032", "CVE-2017-5033", "CVE-2017-5034", "CVE-2017-5035", "CVE-2017-5036", "CVE-2017-5037", "CVE-2017-5038", "CVE-2017-5039", "CVE-2017-5040", "CVE-2017-5041", "CVE-2017-5042", "CVE-2017-5043", "CVE-2017-5044", "CVE-2017-5045", "CVE-2017-5046");
  script_osvdb_id(149635, 151459, 153215, 153330, 153331, 153332, 153333, 153334, 153335, 153336, 153337, 153338, 153339, 153340, 153341, 153342, 153349, 153394, 156236, 156237, 156238, 156239, 156240);
  script_xref(name:"DSA", value:"3810");

  script_name(english:"Debian DSA-3810-1 : chromium-browser - security update");
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

  - CVE-2017-5029
    Holger Fuhrmannek discovered an integer overflow issue
    in the libxslt library.

  - CVE-2017-5030
    Brendon Tiszka discovered a memory corruption issue in
    the v8 JavaScript library.

  - CVE-2017-5031
    Looben Yang discovered a use-after-free issue in the
    ANGLE library.

  - CVE-2017-5032
    Ashfaq Ansari discovered an out-of-bounds write in the
    pdfium library.

  - CVE-2017-5033
    Nicolai Grodum discovered a way to bypass the Content
    Security Policy.

  - CVE-2017-5034
    Ke Liu discovered an integer overflow issue in the
    pdfium library.

  - CVE-2017-5035
    Enzo Aguado discovered an issue with the omnibox.

  - CVE-2017-5036
    A use-after-free issue was discovered in the pdfium
    library.

  - CVE-2017-5037
    Yongke Wang discovered multiple out-of-bounds write
    issues.

  - CVE-2017-5038
    A use-after-free issue was discovered in the guest view.

  - CVE-2017-5039
    jinmo123 discovered a use-after-free issue in the pdfium
    library.

  - CVE-2017-5040
    Choongwoo Han discovered an information disclosure issue
    in the v8 JavaScript library.

  - CVE-2017-5041
    Jordi Chancel discovered an address spoofing issue.

  - CVE-2017-5042
    Mike Ruddy discovered incorrect handling of cookies.

  - CVE-2017-5043
    Another use-after-free issue was discovered in the guest
    view.

  - CVE-2017-5044
    Kushal Arvind Shah discovered a heap overflow issue in
    the skia library.

  - CVE-2017-5045
    Dhaval Kapil discovered an information disclosure issue.

  - CVE-2017-5046
    Masato Kinugawa discovered an information disclosure
    issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5029"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5030"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5033"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5036"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5037"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5039"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5043"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5044"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5045"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5046"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2017/dsa-3810"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (jessie), these problems have been fixed
in version 57.0.2987.98-1~deb8u1.

For the upcoming stable (stretch) and unstable (sid) distributions,
these problems have been fixed in version 57.0.2987.98-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"chromedriver", reference:"57.0.2987.98-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium", reference:"57.0.2987.98-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-dbg", reference:"57.0.2987.98-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-inspector", reference:"57.0.2987.98-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-l10n", reference:"57.0.2987.98-1~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
