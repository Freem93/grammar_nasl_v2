#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-509-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91548);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/06/10 15:24:06 $");

  script_name(english:"Debian DLA-509-1 : samba security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Samba 2:3.6.6-6+deb7u9 release, issued by the DSA-3548-1,
introduced different regressions causing trust relationship with Win 7
domains to fail. The fix for the CVE-2016-2115 has been reverted, so
administrators should set 'client signing = required' instead.

For Debian 7 'Wheezy', these problems have been fixed in version
2:3.6.6-6+deb7u10. More information is available in the NEWS file
included in this samba release.

We recommend that you upgrade your samba packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/06/msg00010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/samba"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-smbpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-common-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:smbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:winbind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/10");
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
if (deb_check(release:"7.0", prefix:"libnss-winbind", reference:"2:3.6.6-6+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libpam-smbpass", reference:"2:3.6.6-6+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libpam-winbind", reference:"2:3.6.6-6+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libsmbclient", reference:"2:3.6.6-6+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libsmbclient-dev", reference:"2:3.6.6-6+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libwbclient-dev", reference:"2:3.6.6-6+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libwbclient0", reference:"2:3.6.6-6+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"samba", reference:"2:3.6.6-6+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"samba-common", reference:"2:3.6.6-6+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"samba-common-bin", reference:"2:3.6.6-6+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"samba-dbg", reference:"2:3.6.6-6+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"samba-doc", reference:"2:3.6.6-6+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"samba-doc-pdf", reference:"2:3.6.6-6+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"samba-tools", reference:"2:3.6.6-6+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"smbclient", reference:"2:3.6.6-6+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"swat", reference:"2:3.6.6-6+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"winbind", reference:"2:3.6.6-6+deb7u10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
