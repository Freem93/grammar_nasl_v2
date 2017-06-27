#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-122. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14959);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/17 23:41:26 $");

  script_cve_id("CVE-2002-0059");
  script_xref(name:"DSA", value:"122");

  script_name(english:"Debian DSA-122-1 : zlib - malloc error (double free)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The compression library zlib has a flaw in which it attempts to free
memory more than once under certain conditions. This can possibly be
exploited to run arbitrary code in a program that includes zlib. If a
network application running as root is linked to zlib, this could
potentially lead to a remote root compromise. No exploits are known at
this time. This vulnerability is assigned the CVE candidate name of
CAN-2002-0059.

The zlib vulnerability is fixed in the Debian zlib package version
1.1.3-5.1. A number of programs either link statically to zlib or
include a private copy of zlib code. These programs must also be
upgraded to eliminate the zlib vulnerability. The affected packages
and fixed versions follow :

  - amaya 2.4-1potato1
  - dictd 1.4.9-9potato1

  - erlang 49.1-10.1

  - freeamp 2.0.6-2.1

  - mirrordir 0.10.48-2.1

  - ppp 2.3.11-1.5

  - rsync 2.3.2-1.6

  - vrweb 1.5-5.1

Those using the pre-release (testing) version of Debian should upgrade
to zlib 1.1.3-19.1 or a later version. Note that since this version of
Debian has not yet been released it may not be available immediately
for all architectures. Debian 2.2 (potato) is the latest supported
release.


We recommend that you upgrade your packages immediately. Note that you
should restart all programs that use the shared zlib library in order
for the fix to take effect. This is most easily done by rebooting the
system."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-122"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected zlib package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"amaya", reference:"2.4-1potato1")) flag++;
if (deb_check(release:"2.2", prefix:"dict", reference:"1.4.9-9potato1")) flag++;
if (deb_check(release:"2.2", prefix:"dictd", reference:"1.4.9-9potato1")) flag++;
if (deb_check(release:"2.2", prefix:"erlang", reference:"49.1-10.1")) flag++;
if (deb_check(release:"2.2", prefix:"erlang-base", reference:"49.1-10.1")) flag++;
if (deb_check(release:"2.2", prefix:"erlang-erl", reference:"49.1-10.1")) flag++;
if (deb_check(release:"2.2", prefix:"erlang-java", reference:"49.1-10.1")) flag++;
if (deb_check(release:"2.2", prefix:"freeamp", reference:"2.0.6-2.1")) flag++;
if (deb_check(release:"2.2", prefix:"freeamp-doc", reference:"2.0.6-2.1")) flag++;
if (deb_check(release:"2.2", prefix:"libfreeamp-alsa", reference:"2.0.6-2.1")) flag++;
if (deb_check(release:"2.2", prefix:"libfreeamp-esound", reference:"2.0.6-2.1")) flag++;
if (deb_check(release:"2.2", prefix:"mirrordir", reference:"0.10.48-2.1")) flag++;
if (deb_check(release:"2.2", prefix:"ppp", reference:"2.3.11-1.5")) flag++;
if (deb_check(release:"2.2", prefix:"rsync", reference:"2.3.2-1.6")) flag++;
if (deb_check(release:"2.2", prefix:"vrweb", reference:"1.5-5.1")) flag++;
if (deb_check(release:"2.2", prefix:"zlib-bin", reference:"1.1.3-5.1")) flag++;
if (deb_check(release:"2.2", prefix:"zlib1", reference:"1.1.3-5.1")) flag++;
if (deb_check(release:"2.2", prefix:"zlib1-altdev", reference:"1.1.3-5.1")) flag++;
if (deb_check(release:"2.2", prefix:"zlib1g", reference:"1.1.3-5.1")) flag++;
if (deb_check(release:"2.2", prefix:"zlib1g-dev", reference:"1.1.3-5.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
