#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-861-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97798);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/20 13:44:33 $");

  script_cve_id("CVE-2016-8714");
  script_osvdb_id(153351);

  script_name(english:"Debian DLA-861-1 : r-base security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An exploitable buffer overflow vulnerability exists in the
LoadEncoding functionality of the R programming language. A specially
crafted R script can cause a buffer overflow resulting in a memory
corruption. An attacker can send a malicious R script to trigger this
vulnerability.

For Debian 7 'Wheezy', this problem has been fixed in version
2.15.1-4+deb7u1.

We recommend that you upgrade your r-base packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/03/msg00018.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/r-base"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:r-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:r-base-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:r-base-core-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:r-base-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:r-base-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:r-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:r-doc-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:r-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:r-mathlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:r-recommended");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/20");
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
if (deb_check(release:"7.0", prefix:"r-base", reference:"2.15.1-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"r-base-core", reference:"2.15.1-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"r-base-core-dbg", reference:"2.15.1-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"r-base-dev", reference:"2.15.1-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"r-base-html", reference:"2.15.1-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"r-doc-html", reference:"2.15.1-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"r-doc-info", reference:"2.15.1-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"r-doc-pdf", reference:"2.15.1-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"r-mathlib", reference:"2.15.1-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"r-recommended", reference:"2.15.1-4+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
