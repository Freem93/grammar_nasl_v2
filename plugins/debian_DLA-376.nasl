#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-376-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87682);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/05 14:32:00 $");

  script_cve_id("CVE-2009-0689");
  script_bugtraq_id(35510, 36565, 36851, 37078, 37080, 37687, 37688);
  script_osvdb_id(55603, 61091, 61186, 61187, 61188, 61189, 62402, 63639, 63641, 63646, 132144);

  script_name(english:"Debian DLA-376-1 : mono security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mono's string-to-double parser may crash, on specially crafted input.
This could theoretically lead to arbitrary code execution.

This issue has been fixed in Debian 6 Squeeze with the version
2.6.7-5.1+deb6u2 of mono. We recommend that you upgrade your mono
packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/12/msg00018.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/mono"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-accessibility1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-accessibility2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-bytefx0.7.6.1-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-bytefx0.7.6.2-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-c5-1.1-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-cairo1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-cairo2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-cecil-private-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-cil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-corlib1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-corlib2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-cscompmgd7.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-cscompmgd8.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-data-tds1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-data-tds2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-data1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-data2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-db2-1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-debugger-soft0.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-firebirdsql1.7-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-getoptions1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-getoptions2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-i18n-west1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-i18n-west2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-i18n1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-i18n2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-ldap1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-ldap2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-management2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-messaging-rabbitmq2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-messaging2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-microsoft-build2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-microsoft7.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-microsoft8.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-npgsql1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-npgsql2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-oracle1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-oracle2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-peapi1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-peapi2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-posix1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-posix2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-profiler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-rabbitmq2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-relaxng1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-relaxng2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-security1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-security2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-sharpzip0.6-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-sharpzip0.84-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-sharpzip2.6-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-sharpzip2.84-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-simd2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-sqlite1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-sqlite2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-data-linq2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-data1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-data2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-ldap1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-ldap2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-messaging1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-messaging2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-runtime1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-runtime2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-mvc1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web-mvc2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system-web2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-system2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-tasklets2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-wcf3.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-webbrowser0.5-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-windowsbase3.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-winforms1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono-winforms2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmono2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-1.0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-1.0-gac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-1.0-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-2.0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-2.0-gac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-2.0-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-complete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-csharp-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-gac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-gmcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-jay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-mcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-mjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-runtime-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono-xbuild");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:monodoc-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:monodoc-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:prj2make-sharp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/04");
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
if (deb_check(release:"6.0", prefix:"libmono-accessibility1.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-accessibility2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-bytefx0.7.6.1-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-bytefx0.7.6.2-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-c5-1.1-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-cairo1.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-cairo2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-cecil-private-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-cil-dev", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-corlib1.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-corlib2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-cscompmgd7.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-cscompmgd8.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-data-tds1.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-data-tds2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-data1.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-data2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-db2-1.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-debugger-soft0.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-dev", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-firebirdsql1.7-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-getoptions1.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-getoptions2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-i18n-west1.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-i18n-west2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-i18n1.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-i18n2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-ldap1.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-ldap2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-management2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-messaging-rabbitmq2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-messaging2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-microsoft-build2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-microsoft7.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-microsoft8.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-npgsql1.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-npgsql2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-oracle1.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-oracle2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-peapi1.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-peapi2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-posix1.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-posix2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-profiler", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-rabbitmq2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-relaxng1.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-relaxng2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-security1.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-security2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-sharpzip0.6-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-sharpzip0.84-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-sharpzip2.6-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-sharpzip2.84-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-simd2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-sqlite1.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-sqlite2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-system-data-linq2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-system-data1.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-system-data2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-system-ldap1.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-system-ldap2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-system-messaging1.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-system-messaging2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-system-runtime1.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-system-runtime2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-system-web-mvc1.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-system-web-mvc2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-system-web1.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-system-web2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-system1.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-system2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-tasklets2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-wcf3.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-webbrowser0.5-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-windowsbase3.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-winforms1.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono-winforms2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono0", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono0-dbg", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono1.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libmono2.0-cil", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"mono-1.0-devel", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"mono-1.0-gac", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"mono-1.0-service", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"mono-2.0-devel", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"mono-2.0-gac", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"mono-2.0-service", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"mono-complete", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"mono-csharp-shell", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"mono-dbg", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"mono-devel", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"mono-gac", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"mono-gmcs", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"mono-jay", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"mono-mcs", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"mono-mjs", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"mono-runtime", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"mono-runtime-dbg", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"mono-utils", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"mono-xbuild", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"monodoc-base", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"monodoc-manual", reference:"2.6.7-5.1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"prj2make-sharp", reference:"2.6.7-5.1+deb6u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
