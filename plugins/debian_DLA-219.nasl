#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-219-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83476);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2015/12/02 20:08:17 $");

  script_cve_id("CVE-2013-1569", "CVE-2013-2383", "CVE-2013-2384", "CVE-2013-2419", "CVE-2014-6585", "CVE-2014-6591", "CVE-2014-7923", "CVE-2014-7926", "CVE-2014-7940", "CVE-2014-9654");
  script_bugtraq_id(59131, 59166, 59179, 59190, 72173, 72175, 72288, 72980);
  script_osvdb_id(92335, 92336, 92337, 92342, 117232, 117233, 117380, 117383, 117397, 117639);

  script_name(english:"Debian DLA-219-1 : icu security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in the International
Components for Unicode (ICU) library :

CVE-2013-1569

Glyph table issue.

CVE-2013-2383

Glyph table issue.

CVE-2013-2384

Font layout issue.

CVE-2013-2419

Font processing issue.

CVE-2014-6585

Out-of-bounds read.

CVE-2014-6591

Additional out-of-bounds reads.

CVE-2014-7923

Memory corruption in regular expression comparison.

CVE-2014-7926

Memory corruption in regular expression comparison.

CVE-2014-7940

Uninitialized memory.

CVE-2014-9654

More regular expression flaws.

For Debian 6 'Squeeze', these issues have been fixed in
icu version 4.4.1-8+squeeze3.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/05/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/icu"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icu-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lib32icu-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lib32icu44");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libicu-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libicu44");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libicu44-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/15");
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
if (deb_check(release:"6.0", prefix:"icu-doc", reference:"4.4.1-8+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"lib32icu-dev", reference:"4.4.1-8+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"lib32icu44", reference:"4.4.1-8+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libicu-dev", reference:"4.4.1-8+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libicu44", reference:"4.4.1-8+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libicu44-dbg", reference:"4.4.1-8+squeeze3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
