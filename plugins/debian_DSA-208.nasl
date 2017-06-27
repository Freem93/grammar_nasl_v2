#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-208. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15045);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/17 23:58:35 $");

  script_cve_id("CVE-2002-1323");
  script_bugtraq_id(6111);
  script_xref(name:"DSA", value:"208");

  script_name(english:"Debian DSA-208-1 : perl - broken safe compartment");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A security hole has been discovered in Safe.pm which is used in all
versions of Perl. The Safe extension module allows the creation of
compartments in which perl code can be evaluated in a new namespace
and the code evaluated in the compartment cannot refer to variables
outside this namespace. However, when a Safe compartment has already
been used, there's no guarantee that it is Safe any longer, because
there's a way for code to be executed within the Safe compartment to
alter its operation mask. Thus, programs that use a Safe compartment
only once aren't affected by this bug."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-208"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Perl packages.

This problem has been fixed in version 5.6.1-8.2 for the current
stable distribution (woody), in version 5.004.05-6.2 and 5.005.03-7.2
for the old stable distribution (potato) and in version 5.8.0-14 for
the unstable distribution (sid)."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl-5.004");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl-5.005");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"perl-5.004", reference:"5.004.05-6.2")) flag++;
if (deb_check(release:"2.2", prefix:"perl-5.004-base", reference:"5.004.05-6.2")) flag++;
if (deb_check(release:"2.2", prefix:"perl-5.004-debug", reference:"5.004.05-6.2")) flag++;
if (deb_check(release:"2.2", prefix:"perl-5.004-doc", reference:"5.004.05-6.2")) flag++;
if (deb_check(release:"2.2", prefix:"perl-5.004-suid", reference:"5.004.05-6.2")) flag++;
if (deb_check(release:"2.2", prefix:"perl-5.005", reference:"5.005.03-7.2")) flag++;
if (deb_check(release:"2.2", prefix:"perl-5.005-base", reference:"5.005.03-7.2")) flag++;
if (deb_check(release:"2.2", prefix:"perl-5.005-debug", reference:"5.005.03-7.2")) flag++;
if (deb_check(release:"2.2", prefix:"perl-5.005-doc", reference:"5.005.03-7.2")) flag++;
if (deb_check(release:"2.2", prefix:"perl-5.005-suid", reference:"5.005.03-7.2")) flag++;
if (deb_check(release:"2.2", prefix:"perl-5.005-thread", reference:"5.005.03-7.2")) flag++;
if (deb_check(release:"3.0", prefix:"libcgi-fast-perl", reference:"5.6.1-8.2")) flag++;
if (deb_check(release:"3.0", prefix:"libperl-dev", reference:"5.6.1-8.2")) flag++;
if (deb_check(release:"3.0", prefix:"libperl5.6", reference:"5.6.1-8.2")) flag++;
if (deb_check(release:"3.0", prefix:"perl", reference:"5.6.1-8.2")) flag++;
if (deb_check(release:"3.0", prefix:"perl-base", reference:"5.6.1-8.2")) flag++;
if (deb_check(release:"3.0", prefix:"perl-debug", reference:"5.6.1-8.2")) flag++;
if (deb_check(release:"3.0", prefix:"perl-doc", reference:"5.6.1-8.2")) flag++;
if (deb_check(release:"3.0", prefix:"perl-modules", reference:"5.6.1-8.2")) flag++;
if (deb_check(release:"3.0", prefix:"perl-suid", reference:"5.6.1-8.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
