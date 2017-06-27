#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-367-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87316);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:23:47 $");

  script_cve_id("CVE-2015-7543");
  script_osvdb_id(131618);

  script_name(english:"Debian DLA-367-1 : kdelibs security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It has been reported that kdelibs uses the insecure mktemp() function
to create the temporary directory it uses to host user-specific
sockets. It is thus possible for another user to hijack this temporary
directory and gain socket accesses it should not have.

In Debian 6 'Squeeze', this issue has been addressed in
kdelibs 3.5.10.dfsg.1-5+deb6u1 with the use of the safer mkdtemp()
function. We recommend that you upgrade your kdelibs packages.

Other Debian releases have newer versions of the libraries (kdelibs4)
that are not affected by this problem.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/12/msg00008.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/kdelibs"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdelibs-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdelibs-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdelibs4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdelibs4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdelibs4c2a");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/11");
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
if (deb_check(release:"6.0", prefix:"kdelibs", reference:"3.5.10.dfsg.1-5+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"kdelibs-data", reference:"3.5.10.dfsg.1-5+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"kdelibs-dbg", reference:"3.5.10.dfsg.1-5+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"kdelibs4-dev", reference:"3.5.10.dfsg.1-5+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"kdelibs4-doc", reference:"3.5.10.dfsg.1-5+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"kdelibs4c2a", reference:"3.5.10.dfsg.1-5+deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
