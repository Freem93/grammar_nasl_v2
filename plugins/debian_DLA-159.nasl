#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-159-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82142);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/05 14:49:54 $");

  script_cve_id("CVE-2014-9679");
  script_bugtraq_id(72594);
  script_osvdb_id(118237);

  script_name(english:"Debian DLA-159-1 : cups security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Peter De Wachter discovered that CUPS, the Common UNIX Printing
System, did not correctly parse compressed raster files. By submitting
a specially crafted raster file, a remote attacker could use this
vulnerability to trigger a buffer overflow.

For the oldstable distribution (squeeze), this problem has been fixed
in version 1.4.4-7+squeeze7.

For the stable distribution (wheezy), this problem has been fixed in
version 1.5.3-5+deb7u5.

We recommend that you upgrade your cups packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/02/msg00013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/cups"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-bsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-ppdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cupsddk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcups2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcups2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupscgi1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupscgi1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsdriver1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsdriver1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsimage2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsimage2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsmime1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsmime1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsppdc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsppdc1-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
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
if (deb_check(release:"6.0", prefix:"cups", reference:"1.4.4-7+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"cups-bsd", reference:"1.4.4-7+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"cups-client", reference:"1.4.4-7+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"cups-common", reference:"1.4.4-7+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"cups-dbg", reference:"1.4.4-7+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"cups-ppdc", reference:"1.4.4-7+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"cupsddk", reference:"1.4.4-7+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libcups2", reference:"1.4.4-7+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libcups2-dev", reference:"1.4.4-7+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libcupscgi1", reference:"1.4.4-7+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libcupscgi1-dev", reference:"1.4.4-7+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsdriver1", reference:"1.4.4-7+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsdriver1-dev", reference:"1.4.4-7+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsimage2", reference:"1.4.4-7+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsimage2-dev", reference:"1.4.4-7+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsmime1", reference:"1.4.4-7+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsmime1-dev", reference:"1.4.4-7+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsppdc1", reference:"1.4.4-7+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsppdc1-dev", reference:"1.4.4-7+squeeze7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
