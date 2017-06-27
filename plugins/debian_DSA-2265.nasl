#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2265. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55280);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:31:55 $");

  script_cve_id("CVE-2011-1487");
  script_bugtraq_id(47124);
  script_osvdb_id(75047);
  script_xref(name:"DSA", value:"2265");

  script_name(english:"Debian DSA-2265-1 : perl - lack of tainted flag propagation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mark Martinec discovered that Perl incorrectly clears the tainted flag
on values returned by case conversion functions such as 'lc'. This may
expose preexisting vulnerabilities in applications which use these
functions while processing untrusted input. No such applications are
known at this stage. Such applications will cease to work when this
security update is applied because taint checks are designed to
prevent such unsafe use of untrusted input data."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=622817"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/perl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2265"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the perl packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 5.10.0-19lenny4.

For the stable distribution (squeeze), this problem has been fixed in
version 5.10.1-17squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"perl", reference:"5.10.0-19lenny4")) flag++;
if (deb_check(release:"6.0", prefix:"libcgi-fast-perl", reference:"5.10.1-17squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libperl-dev", reference:"5.10.1-17squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libperl5.10", reference:"5.10.1-17squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"perl", reference:"5.10.1-17squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"perl-base", reference:"5.10.1-17squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"perl-debug", reference:"5.10.1-17squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"perl-doc", reference:"5.10.1-17squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"perl-modules", reference:"5.10.1-17squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"perl-suid", reference:"5.10.1-17squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
