#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2314. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56381);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2011-3848", "CVE-2011-3869", "CVE-2011-3870", "CVE-2011-3871");
  script_bugtraq_id(49860, 49909);
  script_osvdb_id(75986, 75988, 75989, 76018);
  script_xref(name:"DSA", value:"2314");

  script_name(english:"Debian DSA-2314-1 : puppet - multiple vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues have been discovered in Puppet, a centralized
configuration management system. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2011-3848
    Kristian Erik Hermansen reported that an unauthenticated
    directory traversal could drop any valid X.509
    Certificate Signing Request at any location on disk,
    with the privileges of the Puppet Master application.

  - CVE-2011-3870
    Ricky Zhou discovered a potential local privilege
    escalation in the ssh_authorized_keys resource and
    theoretically in the Solaris and AIX providers, where
    file ownership was given away before it was written,
    leading to a possibility for a user to overwrite
    arbitrary files as root, if their authorized_keys file
    was managed.

  - CVE-2011-3869
    A predictable file name in the k5login type leads to the
    possibility of symlink attacks which would allow the
    owner of the home directory to symlink to anything on
    the system, and have it replaced with the'correct'
    content of the file, which can lead to a privilege
    escalation on puppet runs.

  - CVE-2011-3871
    A potential local privilege escalation was found in the
    --edit mode of 'puppet resource' due to a persistent,
    predictable file name, which can result in editing an
    arbitrary target file, and thus be be tricked into
    running that arbitrary file as the invoking user. This
    command is most commonly run as root, this leads to a
    potential privilege escalation.

Additionally, this update hardens the indirector file backed terminus
base class against injection attacks based on trusted path names."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3869"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/puppet"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2314"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the puppet packages.

For the oldstable distribution (lenny), this problem will be fixed
soon.

For the stable distribution (squeeze), this problem has been fixed in
version 2.6.2-5+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:puppet");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"puppet", reference:"2.6.2-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"puppet-common", reference:"2.6.2-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"puppet-el", reference:"2.6.2-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"puppet-testsuite", reference:"2.6.2-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"puppetmaster", reference:"2.6.2-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"vim-puppet", reference:"2.6.2-5+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
