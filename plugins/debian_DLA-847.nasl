#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-847-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97614);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/17 14:19:06 $");

  script_cve_id("CVE-2016-10243");
  script_osvdb_id(152962);

  script_name(english:"Debian DLA-847-1 : texlive-base security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The TeX system allows for calling external programs from within the
TeX source code. This has been restricted to a small set of programs
since a long time ago.

Unfortunately it turned out that one program in the list, mpost,
allows in turn to specify other programs to be run, which allows
arbitrary code execution when compiling a TeX document.

For Debian 7 'Wheezy', these problems have been fixed in version
2012.20120611-5+deb7u1.

We recommend that you upgrade your texlive-base packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/03/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/texlive-base"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:texlive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:texlive-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:texlive-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:texlive-fonts-recommended");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:texlive-fonts-recommended-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:texlive-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:texlive-generic-recommended");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:texlive-latex-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:texlive-latex-base-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:texlive-latex-recommended");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:texlive-latex-recommended-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:texlive-luatex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:texlive-metapost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:texlive-metapost-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:texlive-omega");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:texlive-pictures");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:texlive-pictures-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:texlive-xetex");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/09");
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
if (deb_check(release:"7.0", prefix:"texlive", reference:"2012.20120611-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"texlive-base", reference:"2012.20120611-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"texlive-common", reference:"2012.20120611-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"texlive-fonts-recommended", reference:"2012.20120611-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"texlive-fonts-recommended-doc", reference:"2012.20120611-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"texlive-full", reference:"2012.20120611-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"texlive-generic-recommended", reference:"2012.20120611-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"texlive-latex-base", reference:"2012.20120611-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"texlive-latex-base-doc", reference:"2012.20120611-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"texlive-latex-recommended", reference:"2012.20120611-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"texlive-latex-recommended-doc", reference:"2012.20120611-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"texlive-luatex", reference:"2012.20120611-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"texlive-metapost", reference:"2012.20120611-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"texlive-metapost-doc", reference:"2012.20120611-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"texlive-omega", reference:"2012.20120611-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"texlive-pictures", reference:"2012.20120611-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"texlive-pictures-doc", reference:"2012.20120611-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"texlive-xetex", reference:"2012.20120611-5+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
