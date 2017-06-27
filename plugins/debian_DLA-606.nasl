#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-606-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93236);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/06 20:03:52 $");

  script_cve_id("CVE-2016-3991", "CVE-2016-5314", "CVE-2016-5315", "CVE-2016-5316", "CVE-2016-5317", "CVE-2016-5320", "CVE-2016-5321", "CVE-2016-5322", "CVE-2016-5323", "CVE-2016-5875");
  script_osvdb_id(137084, 140006, 140007, 140008, 140009, 140016, 140117, 140118);

  script_name(english:"Debian DLA-606-1 : tiff security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were found in the tiff library, potentially
causing denial of services to applications using it.

For Debian 7 'Wheezy', these problems have been fixed in version
4.0.2-6+deb7u6.

We recommend that you upgrade your tiff packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/08/msg00031.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/tiff"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff5-alt-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiffxx5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/31");
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
if (deb_check(release:"7.0", prefix:"libtiff-doc", reference:"4.0.2-6+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libtiff-opengl", reference:"4.0.2-6+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libtiff-tools", reference:"4.0.2-6+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libtiff5", reference:"4.0.2-6+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libtiff5-alt-dev", reference:"4.0.2-6+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libtiff5-dev", reference:"4.0.2-6+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libtiffxx5", reference:"4.0.2-6+deb7u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
