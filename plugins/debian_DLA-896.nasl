#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-896-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(99442);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/19 13:27:09 $");

  script_cve_id("CVE-2017-5373", "CVE-2017-5375", "CVE-2017-5376", "CVE-2017-5378", "CVE-2017-5380", "CVE-2017-5383", "CVE-2017-5390", "CVE-2017-5396", "CVE-2017-5398", "CVE-2017-5400", "CVE-2017-5401", "CVE-2017-5402", "CVE-2017-5404", "CVE-2017-5405", "CVE-2017-5407", "CVE-2017-5408", "CVE-2017-5410");
  script_osvdb_id(150831, 150832, 150834, 150836, 150837, 150858, 150859, 150860, 150861, 150862, 150863, 150864, 150865, 150866, 150875, 150878, 153143, 153173, 153174, 153175, 153176, 153177, 153178, 153179, 153180, 153181, 153182, 153183, 153190, 153191, 153192, 153193, 153195, 153198, 153214);

  script_name(english:"Debian DLA-896-1 : icedove/thunderbird security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues have been found in the Mozilla Thunderbird
mail client: Multiple memory safety errors, buffer overflows and other
implementation errors may lead to the execution of arbitrary code or
spoofing.

With version 45.8 Debian drops it's custom branding from the Icedove
package and ships the mail client as Thunderbird again. Please see the
link below for further information:
https://wiki.debian.org/Thunderbird

Transition packages for the Icedove packages are provided which
automatically upgrade to the new version. Since new binary packages
need to be installed, make sure to allow that in your upgrade
procedure (e.g. by using 'apt-get dist-upgrade' instead of 'apt-get
upgrade').

For Debian 7 'Wheezy', these problems have been fixed in version
1:45.8.0-3~deb7u1.

We recommend that you upgrade your icedove packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/04/msg00021.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/icedove"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.debian.org/Thunderbird"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:calendar-google-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceowl-extension");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/19");
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
if (deb_check(release:"7.0", prefix:"calendar-google-provider", reference:"1:45.8.0-3~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedove", reference:"1:45.8.0-3~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedove-dbg", reference:"1:45.8.0-3~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedove-dev", reference:"1:45.8.0-3~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceowl-extension", reference:"1:45.8.0-3~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
