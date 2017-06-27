#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-943. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22809);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/04/24 13:06:47 $");

  script_cve_id("CVE-2005-3962");
  script_osvdb_id(21345, 22255);
  script_xref(name:"DSA", value:"943");

  script_name(english:"Debian DSA-943-1 : perl - integer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jack Louis discovered an integer overflow in Perl, Larry Wall's
Practical Extraction and Report Language, that allows attackers to
overwrite arbitrary memory and possibly execute arbitrary code via
specially crafted content that is passed to vulnerable format strings
of third-party software.

The old stable distribution (woody) does not seem to be affected by
this problem."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=341542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-943"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the perl packages.

For the stable distribution (sarge) this problem has been fixed in
version 5.8.4-8sarge3."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libcgi-fast-perl", reference:"5.8.4-8sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libperl-dev", reference:"5.8.4-8sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libperl5.8", reference:"5.8.4-8sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"perl", reference:"5.8.4-8sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"perl-base", reference:"5.8.4-8sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"perl-debug", reference:"5.8.4-8sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"perl-doc", reference:"5.8.4-8sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"perl-modules", reference:"5.8.4-8sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"perl-suid", reference:"5.8.4-8sarge3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
