#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-696. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17600);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/18 00:15:58 $");

  script_cve_id("CVE-2005-0448");
  script_osvdb_id(14619);
  script_xref(name:"DSA", value:"696");

  script_name(english:"Debian DSA-696-1 : perl - design flaw");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Paul Szabo discovered another vulnerability in the File::Path::rmtree
function of perl, the popular scripting language. When a process is
deleting a directory tree, a different user could exploit a race
condition to create setuid binaries in this directory tree, provided
that he already had write permissions in any subdirectory of that
tree."
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
    value:"http://www.debian.org/security/2005/dsa-696"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the perl packages.

For the stable distribution (woody) this problem has been fixed in
version 5.6.1-8.9."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"libcgi-fast-perl", reference:"5.6.1-8.9")) flag++;
if (deb_check(release:"3.0", prefix:"libperl-dev", reference:"5.6.1-8.9")) flag++;
if (deb_check(release:"3.0", prefix:"libperl5.6", reference:"5.6.1-8.9")) flag++;
if (deb_check(release:"3.0", prefix:"perl", reference:"5.6.1-8.9")) flag++;
if (deb_check(release:"3.0", prefix:"perl-base", reference:"5.6.1-8.9")) flag++;
if (deb_check(release:"3.0", prefix:"perl-debug", reference:"5.6.1-8.9")) flag++;
if (deb_check(release:"3.0", prefix:"perl-doc", reference:"5.6.1-8.9")) flag++;
if (deb_check(release:"3.0", prefix:"perl-modules", reference:"5.6.1-8.9")) flag++;
if (deb_check(release:"3.0", prefix:"perl-suid", reference:"5.6.1-8.9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
