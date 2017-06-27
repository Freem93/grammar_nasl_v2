#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-940-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100162);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/15 14:02:24 $");

  script_cve_id("CVE-2017-6318");
  script_osvdb_id(154038);

  script_name(english:"Debian DLA-940-1 : sane-backends security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that there was an issue in sane-backends, an API
library for scanners. It allowed remote attackers to obtain sensitive
memory information via a crafted SANE_NET_CONTROL_OPTION packet.

For Debian 7 'Wheezy', this issue has been fixed in sane-backends
version 1.0.22-7.4+deb7u1.

We recommend that you upgrade your sane-backends packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/05/msg00011.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/sane-backends"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsane-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsane-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsane-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sane-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/15");
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
if (deb_check(release:"7.0", prefix:"libsane", reference:"1.0.22-7.4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libsane-common", reference:"1.0.22-7.4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libsane-dbg", reference:"1.0.22-7.4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libsane-dev", reference:"1.0.22-7.4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"sane-utils", reference:"1.0.22-7.4+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
