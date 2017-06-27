#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-946-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100302);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/22 13:36:33 $");

  script_cve_id("CVE-2017-5461", "CVE-2017-5462");
  script_osvdb_id(155952, 155999);

  script_name(english:"Debian DLA-946-1 : nss security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The NSS library is vulnerable to two security issues :

CVE-2017-5461

Out-of-bounds write in Base64 encoding. This can trigger a crash
(denial of service) and might be exploitable for code execution.

CVE-2017-5462

A flaw in DRBG number generation where the internal state V does not
correctly carry bits over.

For Debian 7 'Wheezy', these problems have been fixed in version
2:3.26-1+debu7u3.

We recommend that you upgrade your nss packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/05/msg00017.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/nss"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss3-1d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss3-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/22");
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
if (deb_check(release:"7.0", prefix:"libnss3", reference:"2:3.26-1+debu7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libnss3-1d", reference:"2:3.26-1+debu7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libnss3-dbg", reference:"2:3.26-1+debu7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libnss3-dev", reference:"2:3.26-1+debu7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libnss3-tools", reference:"2:3.26-1+debu7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
