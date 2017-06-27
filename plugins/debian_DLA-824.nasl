#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-824-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97195);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/03/27 13:24:14 $");

  script_cve_id("CVE-2016-10195", "CVE-2016-10196", "CVE-2016-10197");
  script_osvdb_id(151245, 151246, 151247);

  script_name(english:"Debian DLA-824-1 : libevent security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in libevent, an asynchronous
event notification library. They would lead to Denial Of Service via
application crash, or remote code execution.

For Debian 7 'Wheezy', these problems have been fixed in version
2.0.19-stable-3+deb7u2.

We recommend that you upgrade your libevent packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/02/msg00013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libevent"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libevent-2.0-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libevent-core-2.0-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libevent-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libevent-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libevent-extra-2.0-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libevent-openssl-2.0-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libevent-pthreads-2.0-5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/16");
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
if (deb_check(release:"7.0", prefix:"libevent-2.0-5", reference:"2.0.19-stable-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libevent-core-2.0-5", reference:"2.0.19-stable-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libevent-dbg", reference:"2.0.19-stable-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libevent-dev", reference:"2.0.19-stable-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libevent-extra-2.0-5", reference:"2.0.19-stable-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libevent-openssl-2.0-5", reference:"2.0.19-stable-3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libevent-pthreads-2.0-5", reference:"2.0.19-stable-3+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
