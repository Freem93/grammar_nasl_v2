#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1678. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35031);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/05/03 11:20:09 $");

  script_cve_id("CVE-2008-5302", "CVE-2008-5303");
  script_bugtraq_id(12767);
  script_xref(name:"DSA", value:"1678");

  script_name(english:"Debian DSA-1678-1 : perl - design flaws");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Paul Szabo rediscovered a vulnerability in the File::Path::rmtree
function of Perl. It was possible to exploit a race condition to
create setuid binaries in a directory tree or remove arbitrary files
when a process is deleting this tree. This issue was originally known
as CVE-2005-0448 and CVE-2004-0452, which were addressed by DSA-696-1
and DSA-620-1. Unfortunately, they were reintroduced later."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=286905"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=286922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-0448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-0452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1678"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the perl packages.

For the stable distribution (etch), these problems have been fixed in
version 5.8.8-7etch5."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libcgi-fast-perl", reference:"5.8.8-7etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libperl-dev", reference:"5.8.8-7etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libperl5.8", reference:"5.8.8-7etch5")) flag++;
if (deb_check(release:"4.0", prefix:"perl", reference:"5.8.8-7etch5")) flag++;
if (deb_check(release:"4.0", prefix:"perl-base", reference:"5.8.8-7etch5")) flag++;
if (deb_check(release:"4.0", prefix:"perl-debug", reference:"5.8.8-7etch5")) flag++;
if (deb_check(release:"4.0", prefix:"perl-doc", reference:"5.8.8-7etch5")) flag++;
if (deb_check(release:"4.0", prefix:"perl-modules", reference:"5.8.8-7etch5")) flag++;
if (deb_check(release:"4.0", prefix:"perl-suid", reference:"5.8.8-7etch5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
