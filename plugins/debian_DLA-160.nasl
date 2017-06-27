#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-160-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82144);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/02 20:08:16 $");

  script_cve_id("CVE-2014-0106", "CVE-2014-9680");
  script_bugtraq_id(65997, 72649);
  script_osvdb_id(104086, 118397);

  script_name(english:"Debian DLA-160-1 : sudo security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the CVEs described below.

CVE-2014-0106

Todd C. Miller reported that if the env_reset option is disabled in
the sudoers file, the env_delete option is not correctly applied to
environment variables specified on the command line. A malicious user
with sudo permissions may be able to run arbitrary commands with
elevated privileges by manipulating the environment of a command the
user is legitimately allowed to run.

CVE-2014-9680

Jakub Wilk reported that sudo preserves the TZ variable from a user's
environment without any sanitization. A user with sudo access may take
advantage of this to exploit bugs in the C library functions which
parse the TZ environment variable or to open files that the user would
not otherwise be able to open. The latter could potentially cause
changes in system behavior when reading certain device special files
or cause the program run via sudo to block.

For the oldstable distribution (squeeze), these problems have been
fixed in version 1.7.4p4-2.squeeze.5.

For the stable distribution (wheezy), they have been fixed in version
1.8.5p2-1+nmu2.

We recommend that you upgrade your sudo packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/02/msg00014.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/sudo"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected sudo, and sudo-ldap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sudo-ldap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"sudo", reference:"1.7.4p4-2.squeeze.5")) flag++;
if (deb_check(release:"6.0", prefix:"sudo-ldap", reference:"1.7.4p4-2.squeeze.5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
