#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3628. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(92548);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/06 20:25:09 $");

  script_cve_id("CVE-2016-1238", "CVE-2016-6185");
  script_osvdb_id(140809, 142160);
  script_xref(name:"DSA", value:"3628");

  script_name(english:"Debian DSA-3628-1 : perl - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in the implementation of the
Perl programming language. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2016-1238
    John Lightsey and Todd Rinaldo reported that the
    opportunistic loading of optional modules can make many
    programs unintentionally load code from the current
    working directory (which might be changed to another
    directory without the user realising) and potentially
    leading to privilege escalation, as demonstrated in
    Debian with certain combinations of installed packages.

  The problem relates to Perl loading modules from the includes
  directory array ('@INC') in which the last element is the current
  directory ('.'). That means that, when 'perl' wants to load a module
  (during first compilation or during lazy loading of a module in run
  time), perl will look for the module in the current directory at the
  end, since '.' is the last include directory in its array of include
  directories to seek. The issue is with requiring libraries that are
  in '.' but are not otherwise installed.

  With this update several modules which are known to be vulnerable
  are updated to not load modules from current directory.

  Additionally the update allows configurable removal of '.' from @INC
  in /etc/perl/sitecustomize.pl for a transitional period. It is
  recommended to enable this setting if the possible breakage for a
  specific site has been evaluated. Problems in packages provided in
  Debian resulting from the switch to the removal of '.' from @INC
  should be reported to the Perl maintainers at
  perl@packages.debian.org .

  It is planned to switch to the default removal of '.' in @INC in a
  subsequent update to perl via a point release if possible, and in
  any case for the upcoming stable release Debian 9 (stretch).

  - CVE-2016-6185
    It was discovered that XSLoader, a core module from Perl
    to dynamically load C libraries into Perl code, could
    load shared library from incorrect location. XSLoader
    uses caller() information to locate the .so file to
    load. This can be incorrect if XSLoader::load() is
    called in a string eval. An attacker can take advantage
    of this flaw to execute arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=829578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-6185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/perl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3628"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the perl packages.

For the stable distribution (jessie), these problems have been fixed
in version 5.20.2-3+deb8u6. Additionally this update includes the
following updated packages to address optional module loading
vulnerabilities related to CVE-2016-1238, or to address build failures
which occur when '.' is removed from @INC :

  - cdbs 0.4.130+deb8u1
  - debhelper 9.20150101+deb8u2

  - devscripts 2.15.3+deb8u12

  - exim4 4.84.2-2+deb8u12

  - libintl-perl 1.23-1+deb8u12

  - libmime-charset-perl 1.011.1-1+deb8u22

  - libmime-encwords-perl 1.014.3-1+deb8u12

  - libmodule-build-perl 0.421000-2+deb8u12

  - libnet-dns-perl 0.81-2+deb8u12

  - libsys-syslog-perl 0.33-1+deb8u12

  - libunicode-linebreak-perl 0.0.20140601-2+deb8u22"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"libperl-dev", reference:"5.20.2-3+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libperl5.20", reference:"5.20.2-3+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"perl", reference:"5.20.2-3+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"perl-base", reference:"5.20.2-3+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"perl-debug", reference:"5.20.2-3+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"perl-doc", reference:"5.20.2-3+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"perl-modules", reference:"5.20.2-3+deb8u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
