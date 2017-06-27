#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-575-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92638);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/08/05 13:39:55 $");

  script_name(english:"Debian DLA-575-2 : collectd regression update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The previous upload of collectd surfaced a problem in the way the
network plugin initializes gcrypt preventing the plugin from being
loaded when packet signing or encryption is enabled. Previously, this
may have led to program crashes.

For Debian 7 'Wheezy', these problems have been fixed in version
5.1.0-3+deb7u2.

We recommend that you upgrade your collectd packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/08/msg00004.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/collectd"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:collectd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:collectd-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:collectd-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:collectd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:collectd-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcollectdclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcollectdclient0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/01");
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
if (deb_check(release:"7.0", prefix:"collectd", reference:"5.1.0-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"collectd-core", reference:"5.1.0-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"collectd-dbg", reference:"5.1.0-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"collectd-dev", reference:"5.1.0-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"collectd-utils", reference:"5.1.0-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libcollectdclient-dev", reference:"5.1.0-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libcollectdclient0", reference:"5.1.0-3+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
