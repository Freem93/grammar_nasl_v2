#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-565-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92613);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/06 20:03:52 $");

  script_cve_id("CVE-2016-1238", "CVE-2016-6185");
  script_osvdb_id(140809, 142160);

  script_name(english:"Debian DLA-565-1 : perl security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in the implementation of the
Perl programming language. The Common Vulnerabilities and Exposures
project identifies the following problems :

CVE-2016-1238

John Lightsey and Todd Rinaldo reported that the opportunistic loading
of optional modules can make many programs unintentionally load code
from the current working directory (which might be changed to another
directory without the user realising) and potentially leading to
privilege escalation, as demonstrated in Debian with certain
combinations of installed packages.

The problem relates to Perl loading modules from the
includes directory array ('@INC') in which the last element
is the current directory ('.'). That means that, when 'perl'
wants to load a module (during first compilation or during
lazy loading of a module in run- time), perl will look for
the module in the current directory at the end, since '.' is
the last include directory in its array of include
directories to seek. The issue is with requiring libraries
that are in '.' but are not otherwise installed.

With this update several modules which are known to be
vulnerable are updated to not load modules from current
directory.

Additionally the update allows configurable removal of '.'
from @INC in /etc/perl/sitecustomize.pl for a transitional
period. It is recommended to enable this setting if the
possible breakage for a specific site has been evaluated.
Problems in packages provided in Debian resulting from the
switch to the removal of '.' from @INC should be reported to
the Perl maintainers at perl@packages.debian.org .

CVE-2016-6185

It was discovered that XSLoader, a core module from Perl to
dynamically load C libraries into Perl code, could load shared library
from incorrect location. XSLoader uses caller() information to locate
the .so file to load. This can be incorrect if XSLoader::load() is
called in a string eval. An attacker can take advantage of this flaw
to execute arbitrary code.

For Debian 7 'Wheezy', these problems have been fixed in version
5.14.2-21+deb7u4.

We recommend that you upgrade your perl packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/07/msg00027.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/perl"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcgi-fast-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libperl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libperl5.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/29");
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
if (deb_check(release:"7.0", prefix:"libcgi-fast-perl", reference:"5.14.2-21+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libperl-dev", reference:"5.14.2-21+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libperl5.14", reference:"5.14.2-21+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"perl", reference:"5.14.2-21+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"perl-base", reference:"5.14.2-21+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"perl-debug", reference:"5.14.2-21+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"perl-doc", reference:"5.14.2-21+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"perl-modules", reference:"5.14.2-21+deb7u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
