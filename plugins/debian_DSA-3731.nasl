#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3731. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(95667);
  script_version("$Revision: 3.10 $");
  script_cvs_date("$Date: 2017/02/06 16:27:35 $");

  script_cve_id("CVE-2016-5181", "CVE-2016-5182", "CVE-2016-5183", "CVE-2016-5184", "CVE-2016-5185", "CVE-2016-5186", "CVE-2016-5187", "CVE-2016-5188", "CVE-2016-5189", "CVE-2016-5190", "CVE-2016-5191", "CVE-2016-5192", "CVE-2016-5193", "CVE-2016-5194", "CVE-2016-5198", "CVE-2016-5199", "CVE-2016-5200", "CVE-2016-5201", "CVE-2016-5202", "CVE-2016-5203", "CVE-2016-5204", "CVE-2016-5205", "CVE-2016-5206", "CVE-2016-5207", "CVE-2016-5208", "CVE-2016-5209", "CVE-2016-5210", "CVE-2016-5211", "CVE-2016-5212", "CVE-2016-5213", "CVE-2016-5214", "CVE-2016-5215", "CVE-2016-5216", "CVE-2016-5217", "CVE-2016-5218", "CVE-2016-5219", "CVE-2016-5220", "CVE-2016-5221", "CVE-2016-5222", "CVE-2016-5223", "CVE-2016-5224", "CVE-2016-5225", "CVE-2016-5226", "CVE-2016-9650", "CVE-2016-9651", "CVE-2016-9652");
  script_osvdb_id(145564, 145565, 145566, 145567, 145568, 145569, 145570, 145571, 145572, 145573, 145574, 145575, 145576, 145577, 145578, 145580, 145581, 145582, 145583, 145584, 146629, 146996, 146997, 146998, 146999, 148065, 148066, 148067, 148068, 148069, 148070, 148071, 148072, 148073, 148074, 148075, 148076, 148077, 148078, 148079, 148080, 148081, 148082, 148083, 148084, 148086, 148087, 148088, 148104, 148105, 148106, 148110, 148111, 148133, 148134, 148135, 148138, 148139, 148140, 148142);
  script_xref(name:"DSA", value:"3731");

  script_name(english:"Debian DSA-3731-1 : chromium-browser - security update");
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

  - CVE-2016-5181
    A cross-site scripting issue was discovered.

  - CVE-2016-5182
    Giwan Go discovered a heap overflow issue.

  - CVE-2016-5183
    A use-after-free issue was discovered in the pdfium
    library.

  - CVE-2016-5184
    Another use-after-free issue was discovered in the
    pdfium library.

  - CVE-2016-5185
    cloudfuzzer discovered a use-after-free issue in
    Blink/Webkit.

  - CVE-2016-5186
    Abdulrahman Alqabandi discovered an out-of-bounds read
    issue in the developer tools.

  - CVE-2016-5187
    Luan Herrera discovered a URL spoofing issue.

  - CVE-2016-5188
    Luan Herrera discovered that some drop down menus can be
    used to hide parts of the user interface.

  - CVE-2016-5189
    xisigr discovered a URL spoofing issue.

  - CVE-2016-5190
    Atte Kettunen discovered a use-after-free issue.

  - CVE-2016-5191
    Gareth Hughes discovered a cross-site scripting issue.

  - CVE-2016-5192
    haojunhou@gmail.com discovered a same-origin bypass.

  - CVE-2016-5193
    Yuyang Zhou discovered a way to pop open a new window.

  - CVE-2016-5194
    The chrome development team found and fixed various
    issues during internal auditing.

  - CVE-2016-5198
    Tencent Keen Security Lab discovered an out-of-bounds
    memory access issue in the v8 JavaScript library.

  - CVE-2016-5199
    A heap corruption issue was discovered in the ffmpeg
    library.

  - CVE-2016-5200
    Choongwoo Han discovered an out-of-bounds memory access
    issue in the v8 JavaScript library.

  - CVE-2016-5201
    Rob Wu discovered an information leak.

  - CVE-2016-5202
    The chrome development team found and fixed various
    issues during internal auditing.

  - CVE-2016-5203
    A use-after-free issue was discovered in the pdfium
    library.

  - CVE-2016-5204
    Mariusz Mlynski discovered a cross-site scripting issue
    in SVG image handling.

  - CVE-2016-5205
    A cross-site scripting issue was discovered.

  - CVE-2016-5206
    Rob Wu discovered a same-origin bypass in the pdfium
    library.

  - CVE-2016-5207
    Mariusz Mlynski discovered a cross-site scripting issue.

  - CVE-2016-5208
    Mariusz Mlynski discovered another cross-site scripting
    issue.

  - CVE-2016-5209
    Giwan Go discovered an out-of-bounds write issue in
    Blink/Webkit.

  - CVE-2016-5210
    Ke Liu discovered an out-of-bounds write in the pdfium
    library.

  - CVE-2016-5211
    A use-after-free issue was discovered in the pdfium
    library.

  - CVE-2016-5212
    Khalil Zhani discovered an information disclosure issue
    in the developer tools.

  - CVE-2016-5213
    Khalil Zhani discovered a use-after-free issue in the v8
    JavaScript library.

  - CVE-2016-5214
    Jonathan Birch discovered a file download protection
    bypass.

  - CVE-2016-5215
    Looben Yang discovered a use-after-free issue.

  - CVE-2016-5216
    A use-after-free issue was discovered in the pdfium
    library.

  - CVE-2016-5217
    Rob Wu discovered a condition where data was not
    validated by the pdfium library.

  - CVE-2016-5218
    Abdulrahman Alqabandi discovered a URL spoofing issue.

  - CVE-2016-5219
    Rob Wu discovered a use-after-free issue in the v8
    JavaScript library.

  - CVE-2016-5220
    Rob Wu discovered a way to access files on the local
    system.

  - CVE-2016-5221
    Tim Becker discovered an integer overflow issue in the
    angle library.

  - CVE-2016-5222
    xisigr discovered a URL spoofing issue.

  - CVE-2016-5223
    Hwiwon Lee discovered an integer overflow issue in the
    pdfium library.

  - CVE-2016-5224
    Roeland Krak discovered a same-origin bypass in SVG
    image handling.

  - CVE-2016-5225
    Scott Helme discovered a Content Security Protection
    bypass.

  - CVE-2016-5226
    Jun Kokatsu discovered a cross-scripting issue.

  - CVE-2016-9650
    Jakub Zoczek discovered a Content Security Protection
    information disclosure.

  - CVE-2016-9651
    Guang Gong discovered a way to access private data in
    the v8 JavaScript library.

  - CVE-2016-9652
    The chrome development team found and fixed various
    issues during internal auditing."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5194"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5203"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5208"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5210"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5212"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5215"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5216"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5217"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5219"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5222"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5225"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5226"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-9650"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-9651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-9652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3731"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (jessie), these problems have been fixed
in version 55.0.2883.75-1~deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"chromedriver", reference:"55.0.2883.75-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium", reference:"55.0.2883.75-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-dbg", reference:"55.0.2883.75-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-inspector", reference:"55.0.2883.75-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-l10n", reference:"55.0.2883.75-1~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
