#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-228-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83886);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/18 16:42:52 $");

  script_cve_id("CVE-2015-3885");
  script_bugtraq_id(74590);
  script_osvdb_id(121925);

  script_name(english:"Debian DLA-228-1 : exactimage security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability has been discovered in the ExactImage image
manipulation programs.

CVE-2015-3885

Eduardo Castellanos discovered an Integer overflow in the dcraw
version included in ExactImage. This vulnerability allows remote
attackers to cause a denial of service (crash) via a crafted image.

For the oldoldstable distribution (squeeze), these problems have been
fixed in version 0.8.1-3+deb6u4.

For the oldstable, stable, and testing distributions, these problems
will be fixed soon.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/05/msg00015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/exactimage"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exactimage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exactimage-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exactimage-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libexactimage-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-exactimage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-exactimage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/29");
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
if (deb_check(release:"6.0", prefix:"exactimage", reference:"0.8.1-3+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"exactimage-dbg", reference:"0.8.1-3+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"exactimage-perl", reference:"0.8.1-3+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"libexactimage-perl", reference:"0.8.1-3+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"php5-exactimage", reference:"0.8.1-3+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"python-exactimage", reference:"0.8.1-3+deb6u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
