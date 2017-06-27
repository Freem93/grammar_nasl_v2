#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3725. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95361);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2016/12/06 20:34:49 $");

  script_cve_id("CVE-2014-9911", "CVE-2015-2632", "CVE-2015-4844", "CVE-2016-0494", "CVE-2016-6293", "CVE-2016-7415");
  script_osvdb_id(108185, 124628, 129125, 133156, 141943, 144259);
  script_xref(name:"DSA", value:"3725");

  script_name(english:"Debian DSA-3725-1 : icu - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in the International
Components for Unicode (ICU) library.

  - CVE-2014-9911
    Michele Spagnuolo discovered a buffer overflow
    vulnerability which might allow remote attackers to
    cause a denial of service or possibly execute arbitrary
    code via crafted text.

  - CVE-2015-2632
    An integer overflow vulnerability might lead into a
    denial of service or disclosure of portion of
    application memory if an attacker has control on the
    input file.

  - CVE-2015-4844
    Buffer overflow vulnerabilities might allow an attacker
    with control on the font file to perform a denial of
    service or, possibly, execute arbitrary code.

  - CVE-2016-0494
    Integer signedness issues were introduced as part of the
    CVE-2015-4844 fix.

  - CVE-2016-6293
    A buffer overflow might allow an attacker to perform a
    denial of service or disclosure of portion of
    application memory.

  - CVE-2016-7415
    A stack-based buffer overflow might allow an attacker
    with control on the locale string to perform a denial of
    service and, possibly, execute arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=838694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-2632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-0494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-6293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-7415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/icu"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3725"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the icu packages.

For the stable distribution (jessie), these problems have been fixed
in version 52.1-8+deb8u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UR");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:U/RC:R");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/28");
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
if (deb_check(release:"8.0", prefix:"icu-devtools", reference:"52.1-8+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"icu-doc", reference:"52.1-8+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libicu-dev", reference:"52.1-8+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libicu52", reference:"52.1-8+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libicu52-dbg", reference:"52.1-8+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
