#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3324. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85163);
  script_version("$Revision: 2.11 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2015-2721", "CVE-2015-2724", "CVE-2015-2734", "CVE-2015-2735", "CVE-2015-2736", "CVE-2015-2737", "CVE-2015-2738", "CVE-2015-2739", "CVE-2015-2740", "CVE-2015-4000");
  script_osvdb_id(122331, 124070, 124071, 124072, 124073, 124095, 124096, 124097, 124098, 124099, 124100, 124101, 124105);
  script_xref(name:"DSA", value:"3324");

  script_name(english:"Debian DSA-3324-1 : icedove - security update (Logjam)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues have been found in Icedove, Debian's version
of the Mozilla Thunderbird mail client: multiple memory safety errors,
use-after-frees and other implementation errors may lead to the
execution of arbitrary code or denial of service. This update also
addresses a vulnerability in DHE key processing commonly known as the
'LogJam' vulnerability."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/icedove"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/icedove"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3324"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the icedove packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 31.8.0-1~deb7u1.

For the stable distribution (jessie), these problems have been fixed
in version 31.8.0-1~deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/01");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/03");
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
if (deb_check(release:"7.0", prefix:"calendar-google-provider", reference:"31.8.0-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedove", reference:"31.8.0-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedove-dbg", reference:"31.8.0-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedove-dev", reference:"31.8.0-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceowl-extension", reference:"31.8.0-1~deb7u1")) flag++;
if (deb_check(release:"8.0", prefix:"calendar-google-provider", reference:"31.8.0-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"icedove", reference:"31.8.0-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"icedove-dbg", reference:"31.8.0-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"icedove-dev", reference:"31.8.0-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceowl-extension", reference:"31.8.0-1~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
