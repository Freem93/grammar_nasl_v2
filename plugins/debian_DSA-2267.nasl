#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2267. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55487);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2010-1447");
  script_bugtraq_id(40305);
  script_xref(name:"DSA", value:"2267");

  script_name(english:"Debian DSA-2267-1 : perl - restriction bypass");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Perl's Safe module - a module to compile and
execute code in restricted compartments - could be bypassed.

Please note that this update is known to break Petal, an XML-based
templating engine (shipped with Debian 6.0/Squeeze in the package
libpetal-perl, see bug #582805 for details). A fix is not yet
available. If you use Petal, you might consider to put the previous
Perl packages on hold."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=631529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=582805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/perl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2267"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the perl packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 5.10.0-19lenny5.

For the stable distribution (squeeze), this problem has been fixed in
version 5.10.1-17squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/05");
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
if (deb_check(release:"5.0", prefix:"perl", reference:"5.10.0-19lenny5")) flag++;
if (deb_check(release:"6.0", prefix:"libcgi-fast-perl", reference:"5.10.1-17squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libperl-dev", reference:"5.10.1-17squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libperl5.10", reference:"5.10.1-17squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"perl", reference:"5.10.1-17squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"perl-base", reference:"5.10.1-17squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"perl-debug", reference:"5.10.1-17squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"perl-doc", reference:"5.10.1-17squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"perl-modules", reference:"5.10.1-17squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"perl-suid", reference:"5.10.1-17squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
