#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2641. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65178);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/05 14:58:43 $");

  script_cve_id("CVE-2013-1667");
  script_bugtraq_id(58311);
  script_osvdb_id(90892);
  script_xref(name:"DSA", value:"2641");

  script_name(english:"Debian DSA-2641-2 : perl - rehashing flaw");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Yves Orton discovered a flaw in the rehashing code of Perl. This flaw
could be exploited to carry out a denial of service attack against
code that uses arbitrary user input as hash keys. Specifically an
attacker could create a set of keys of a hash causing a denial of
service via memory exhaustion."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=702296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=702821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/perl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/libapache2-mod-perl2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2641"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the perl and libapache2-mod-perl2 packages.

For the stable distribution (squeeze), this problem has been fixed in
version 5.10.1-17squeeze6 of perl.

For the stable distribution (squeeze), this problem has been fixed in
version 2.0.4-7+squeeze1 of libapache2-mod-perl2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-perl2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libapache2-mod-perl2", reference:"2.0.4-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libapache2-mod-perl2-dev", reference:"2.0.4-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libapache2-mod-perl2-doc", reference:"2.0.4-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libcgi-fast-perl", reference:"5.10.1-17squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libperl-dev", reference:"5.10.1-17squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libperl5.10", reference:"5.10.1-17squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"perl", reference:"5.10.1-17squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"perl-base", reference:"5.10.1-17squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"perl-debug", reference:"5.10.1-17squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"perl-doc", reference:"5.10.1-17squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"perl-modules", reference:"5.10.1-17squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"perl-suid", reference:"5.10.1-17squeeze6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
