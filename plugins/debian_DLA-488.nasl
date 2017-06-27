#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-488-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91324);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/06 20:03:51 $");

  script_cve_id("CVE-2016-2054", "CVE-2016-2055", "CVE-2016-2056", "CVE-2016-2058");
  script_osvdb_id(134575, 134577, 134578, 134580, 134581, 134582);

  script_name(english:"Debian DLA-488-1 : xymon security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Markus Krell discovered that Xymon (formerly known as Hobbit), a
network- and applications-monitoring system, was vulnerable to the
following security issues :

CVE-2016-2054

The incorrect handling of user-supplied input in the 'config' command
can trigger a stack-based buffer overflow, resulting in denial of
service (via application crash) or remote code execution.

CVE-2016-2055

The incorrect handling of user-supplied input in the 'config' command
can lead to an information leak by serving sensitive configuration
files to a remote user.

CVE-2016-2056

The commands handling password management do not properly validate
user-supplied input, and are thus vulnerable to shell command
injection by a remote user.

CVE-2016-2058

Incorrect escaping of user-supplied input in status webpages can be
used to trigger reflected cross-site scripting attacks.

For Debian 7 'Wheezy', these problems have been fixed in version
4.3.0~beta2.dfsg-9.1+deb7u1.

We recommend that you upgrade your xymon packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/05/msg00040.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/xymon"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected xymon, and xymon-client packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xymon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xymon-client");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/26");
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
if (deb_check(release:"7.0", prefix:"xymon", reference:"4.3.0~beta2.dfsg-9.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"xymon-client", reference:"4.3.0~beta2.dfsg-9.1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
