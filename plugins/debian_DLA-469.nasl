#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-469-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91109);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/05/13 15:33:31 $");

  script_cve_id("CVE-2015-7542");
  script_osvdb_id(131639);

  script_name(english:"Debian DLA-469-1 : libgwenhywfar security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that libgwenhywfar (an OS abstraction layer that
allows porting of software to different operating systems like Linux,

*BSD, Windows etc.) used an outdated CA certificate bundle.

For Debian 7 'Wheezy', this issue has been fixed in libgwenhywfar
version 4.3.3-1+deb7u1 by utilising the ca-certificates package.

We recommend that you upgrade your libgwenhywfar packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/05/msg00020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libgwenhywfar"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gwenhywfar-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgwengui-fox16-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgwengui-gtk2-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgwengui-qt4-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgwenhywfar-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgwenhywfar-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgwenhywfar60");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgwenhywfar60-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgwenhywfar60-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/13");
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
if (deb_check(release:"7.0", prefix:"gwenhywfar-tools", reference:"4.3.3-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgwengui-fox16-0", reference:"4.3.3-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgwengui-gtk2-0", reference:"4.3.3-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgwengui-qt4-0", reference:"4.3.3-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgwenhywfar-data", reference:"4.3.3-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgwenhywfar-doc", reference:"4.3.3-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgwenhywfar60", reference:"4.3.3-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgwenhywfar60-dbg", reference:"4.3.3-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgwenhywfar60-dev", reference:"4.3.3-1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
