#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-707-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94764);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/01/27 23:31:26 $");

  script_cve_id("CVE-2016-7032", "CVE-2016-7076");
  script_osvdb_id(146413, 146414);

  script_name(english:"Debian DLA-707-1 : sudo security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the sudo noexec restriction could have been
bypassed if application run via sudo executed system(), popen() or
wordexp() C library functions with a user-supplied argument. A local
user permitted to run such application via sudo with noexec
restriction could possibly use this flaw to execute arbitrary commands
with elevated privileges.

CVE-2016-7032

noexec bypass via system() and popen()

CVE-2016-7076

noexec bypass via wordexp()

For Debian 7 'Wheezy', these problems have been fixed in version
1.8.5p2-1+nmu3+deb7u2.

We recommend that you upgrade your sudo packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/11/msg00014.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/sudo"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected sudo, and sudo-ldap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sudo-ldap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/15");
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
if (deb_check(release:"7.0", prefix:"sudo", reference:"1.8.5p2-1+nmu3+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"sudo-ldap", reference:"1.8.5p2-1+nmu3+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
