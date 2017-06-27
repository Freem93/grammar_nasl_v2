#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-441-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89041);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/03/01 14:49:47 $");

  script_name(english:"Debian DLA-441-1 : pcre3 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"HP's Zero Day Initiative has identified a vulnerability affecting the
pcre3 package. It was assigned ZDI id ZDI-CAN-3542. A CVE identifier
has not been assigned yet.

PCRE Regular Expression Compilation Stack Buffer Overflow Remote Code
Execution Vulnerability.

PCRE did not validate that handling the (*ACCEPT) verb will occur
within the bounds of the cworkspace stack buffer, leading to a stack
buffer overflow.

For Debian 6 'Squeeze', these problems have been fixed in version
8.02-1.1+deb6u1.

We recommend that you upgrade your pcre3 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/02/msg00032.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/pcre3"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpcre3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpcre3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpcre3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpcre3-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpcrecpp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pcregrep");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/01");
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
if (deb_check(release:"6.0", prefix:"libpcre3", reference:"8.02-1.1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libpcre3-dbg", reference:"8.02-1.1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libpcre3-dev", reference:"8.02-1.1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libpcre3-udeb", reference:"8.02-1.1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libpcrecpp0", reference:"8.02-1.1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"pcregrep", reference:"8.02-1.1+deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
