#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-762-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96097);
  script_version("$Revision: 3.5 $");
  script_cvs_date("$Date: 2017/03/08 15:07:20 $");

  script_cve_id("CVE-2016-9963");
  script_osvdb_id(148832);

  script_name(english:"Debian DLA-762-1 : exim4 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Bjoern Jacke discovered that Exim, Debian's default mail transfer
agent, may leak the private DKIM signing key to the log files if
specific configuration options are met.

For Debian 7 'Wheezy', these problems have been fixed in version
4.80-7+deb7u4.

We recommend that you upgrade your exim4 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/12/msg00038.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/exim4"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4-daemon-heavy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4-daemon-heavy-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4-daemon-light");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4-daemon-light-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:eximon4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"exim4", reference:"4.80-7+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"exim4-base", reference:"4.80-7+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"exim4-config", reference:"4.80-7+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"exim4-daemon-heavy", reference:"4.80-7+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"exim4-daemon-heavy-dbg", reference:"4.80-7+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"exim4-daemon-light", reference:"4.80-7+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"exim4-daemon-light-dbg", reference:"4.80-7+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"exim4-dbg", reference:"4.80-7+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"exim4-dev", reference:"4.80-7+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"eximon4", reference:"4.80-7+deb7u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
