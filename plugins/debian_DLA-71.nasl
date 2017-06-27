#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-71-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82216);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:49:55 $");

  script_cve_id("CVE-2013-5704", "CVE-2014-3581");
  script_bugtraq_id(66550, 71656);
  script_osvdb_id(105190, 112168);

  script_name(english:"Debian DLA-71-1 : apache2 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes two security issues with apache2.

CVE-2013-5704

Disable the possibility to replace HTTP headers with HTTP trailers as
this could be used to circumvent earlier header operations made by
other modules. This can be restored with a new MergeTrailers
directive.

CVE-2014-3581

Fix denial of service where Apache can segfault when mod_cache is used
and when the cached request contains an empty Content-Type header.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2014/10/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/apache2"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-mpm-event");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-mpm-itk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-mpm-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-mpm-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-prefork-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-suexec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-suexec-custom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-threaded-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2.2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2.2-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/16");
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
if (deb_check(release:"6.0", prefix:"apache2", reference:"2.2.16-6+squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-dbg", reference:"2.2.16-6+squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-doc", reference:"2.2.16-6+squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-mpm-event", reference:"2.2.16-6+squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-mpm-itk", reference:"2.2.16-6+squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-mpm-prefork", reference:"2.2.16-6+squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-mpm-worker", reference:"2.2.16-6+squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-prefork-dev", reference:"2.2.16-6+squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-suexec", reference:"2.2.16-6+squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-suexec-custom", reference:"2.2.16-6+squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-threaded-dev", reference:"2.2.16-6+squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-utils", reference:"2.2.16-6+squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"apache2.2-bin", reference:"2.2.16-6+squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"apache2.2-common", reference:"2.2.16-6+squeeze14")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
