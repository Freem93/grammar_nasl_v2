#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-871-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97966);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/27 13:24:15 $");

  script_cve_id("CVE-2016-0772");
  script_osvdb_id(140038);

  script_name(english:"Debian DLA-871-1 : python3.2 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that there was a TLS stripping vulnerability in the
smptlib library distributed with the CPython interpreter.

The library did not return an error if StartTLS failed, which might
have allowed man-in-the-middle attackers to bypass the TLS protections
by leveraging a network position to block the StartTLS command.

For Debian 7 'Wheezy', this issue has been fixed in python3.2 version
3.2.3-7+deb7u1.

We recommend that you upgrade your python3.2 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/03/msg00029.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/python3.2"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:idle-python3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.2-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.2-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/27");
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
if (deb_check(release:"7.0", prefix:"idle-python3.2", reference:"3.2.3-7+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpython3.2", reference:"3.2.3-7+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python3.2", reference:"3.2.3-7+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python3.2-dbg", reference:"3.2.3-7+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python3.2-dev", reference:"3.2.3-7+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python3.2-doc", reference:"3.2.3-7+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python3.2-examples", reference:"3.2.3-7+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python3.2-minimal", reference:"3.2.3-7+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
