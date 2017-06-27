#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1400. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27804);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/04/28 18:23:48 $");

  script_cve_id("CVE-2007-5116");
  script_osvdb_id(40409);
  script_xref(name:"DSA", value:"1400");

  script_name(english:"Debian DSA-1400-1 : perl - heap overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Will Drewry and Tavis Ormandy of the Google Security Team have
discovered a UTF-8 related heap overflow in Perl's regular expression
compiler, probably allowing attackers to execute arbitrary code by
compiling specially crafted regular expressions."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1400"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the perl package.

For the old stable distribution (sarge), this problem has been fixed
in version 5.8.4-8sarge6.

For the stable distribution (etch), this problem has been fixed in
version 5.8.8-7etch1.

Some architectures are missing from this DSA; these updates will be
released once they are available."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libcgi-fast-perl", reference:"5.8.4-8sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"libperl-dev", reference:"5.8.4-8sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"libperl5.8", reference:"5.8.4-8sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"perl", reference:"5.8.4-8sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"perl-base", reference:"5.8.4-8sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"perl-debug", reference:"5.8.4-8sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"perl-doc", reference:"5.8.4-8sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"perl-modules", reference:"5.8.4-8sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"perl-suid", reference:"5.8.4-8sarge6")) flag++;
if (deb_check(release:"4.0", prefix:"libcgi-fast-perl", reference:"5.8.8-7etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libperl-dev", reference:"5.8.8-7etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libperl5.8", reference:"5.8.8-7etch1")) flag++;
if (deb_check(release:"4.0", prefix:"perl", reference:"5.8.8-7etch1")) flag++;
if (deb_check(release:"4.0", prefix:"perl-base", reference:"5.8.8-7etch1")) flag++;
if (deb_check(release:"4.0", prefix:"perl-debug", reference:"5.8.8-7etch1")) flag++;
if (deb_check(release:"4.0", prefix:"perl-doc", reference:"5.8.8-7etch1")) flag++;
if (deb_check(release:"4.0", prefix:"perl-modules", reference:"5.8.8-7etch1")) flag++;
if (deb_check(release:"4.0", prefix:"perl-suid", reference:"5.8.8-7etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
