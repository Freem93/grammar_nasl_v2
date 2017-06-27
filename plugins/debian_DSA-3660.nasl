#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3660. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(93325);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/06 20:25:09 $");

  script_cve_id("CVE-2016-5147", "CVE-2016-5148", "CVE-2016-5149", "CVE-2016-5150", "CVE-2016-5151", "CVE-2016-5152", "CVE-2016-5153", "CVE-2016-5154", "CVE-2016-5155", "CVE-2016-5156", "CVE-2016-5157", "CVE-2016-5158", "CVE-2016-5159", "CVE-2016-5160", "CVE-2016-5161", "CVE-2016-5162", "CVE-2016-5163", "CVE-2016-5164", "CVE-2016-5165", "CVE-2016-5166", "CVE-2016-5167");
  script_osvdb_id(142663, 142664, 142772, 143642, 143643, 143644, 143645, 143646, 143647, 143648, 143649, 143650, 143651, 143652, 143653, 143654, 143655, 143656, 143657, 143658, 143659, 143688, 143718, 143720, 143723, 143724, 143726, 143727, 143737, 143744, 143746, 143747, 143752);
  script_xref(name:"DSA", value:"3660");

  script_name(english:"Debian DSA-3660-1 : chromium-browser - security update");
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

  - CVE-2016-5147
    A cross-site scripting issue was discovered.

  - CVE-2016-5148
    Another cross-site scripting issue was discovered.

  - CVE-2016-5149
    Max Justicz discovered a script injection issue in
    extension handling.

  - CVE-2016-5150
    A use-after-free issue was discovered in Blink/Webkit.

  - CVE-2016-5151
    A use-after-free issue was discovered in the pdfium
    library.

  - CVE-2016-5152
    GiWan Go discovered a heap overflow issue in the pdfium
    library.

  - CVE-2016-5153
    Atte Kettunen discovered a use-after-destruction issue.

  - CVE-2016-5154
    A heap overflow issue was discovered in the pdfium
    library.

  - CVE-2016-5155
    An address bar spoofing issue was discovered.

  - CVE-2016-5156
    jinmo123 discovered a use-after-free issue.

  - CVE-2016-5157
    A heap overflow issue was discovered in the pdfium
    library.

  - CVE-2016-5158
    GiWan Go discovered a heap overflow issue in the pdfium
    library.

  - CVE-2016-5159
    GiWan Go discovered another heap overflow issue in the
    pdfium library.

  - CVE-2016-5160
    @l33terally discovered an extensions resource bypass.

  - CVE-2016-5161
    A type confusion issue was discovered.

  - CVE-2016-5162
    Nicolas Golubovic discovered an extensions resource
    bypass.

  - CVE-2016-5163
    Rafay Baloch discovered an address bar spoofing issue.

  - CVE-2016-5164
    A cross-site scripting issue was discovered in the
    developer tools.

  - CVE-2016-5165
    Gregory Panakkal discovered a script injection issue in
    the developer tools.

  - CVE-2016-5166
    Gregory Panakkal discovered an issue with the Save Page
    As feature.

  - CVE-2016-5167
    The chrome development team found and fixed various
    issues during internal auditing."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5149"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5151"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5167"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3660"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (jessie), these problems have been fixed
in version 53.0.2785.89-1~deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"chromedriver", reference:"53.0.2785.89-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium", reference:"53.0.2785.89-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-dbg", reference:"53.0.2785.89-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-inspector", reference:"53.0.2785.89-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-l10n", reference:"53.0.2785.89-1~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
