#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-76-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82221);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/12/02 20:16:13 $");

  script_cve_id("CVE-2014-5033");
  script_bugtraq_id(68771);

  script_name(english:"Debian DLA-76-1 : kde4libs security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that KAuth, part of kdelibs, uses polkit in a way
that is prone to a race condition that may allow authorization bypass.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2014/10/msg00009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/kde4libs"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdelibs-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdelibs5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdelibs5-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdelibs5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdelibs5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdelibs5-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdoctools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkde3support4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkdecore5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkdesu5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkdeui5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkdewebkit5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkdnssd4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkfile4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkhtml5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkimproxy4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkio5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkjsapi4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkjsembed4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkmediaplayer4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libknewstuff2-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libknewstuff3-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libknotifyconfig4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkntlm4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkparts4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkpty4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrosscore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrossui4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libktexteditor4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkunitconversion4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkutils4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnepomuk4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnepomukquery4a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libplasma3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsolid4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libthreadweaver4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
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
if (deb_check(release:"6.0", prefix:"kdelibs-bin", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"kdelibs5", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"kdelibs5-data", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"kdelibs5-dbg", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"kdelibs5-dev", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"kdelibs5-plugins", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"kdoctools", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libkde3support4", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libkdecore5", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libkdesu5", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libkdeui5", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libkdewebkit5", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libkdnssd4", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libkfile4", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libkhtml5", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libkimproxy4", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libkio5", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libkjsapi4", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libkjsembed4", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libkmediaplayer4", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libknewstuff2-4", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libknewstuff3-4", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libknotifyconfig4", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libkntlm4", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libkparts4", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libkpty4", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libkrosscore4", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libkrossui4", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libktexteditor4", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libkunitconversion4", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libkutils4", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libnepomuk4", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libnepomukquery4a", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libplasma3", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libsolid4", reference:"4:4.4.5-2+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libthreadweaver4", reference:"4:4.4.5-2+squeeze4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
