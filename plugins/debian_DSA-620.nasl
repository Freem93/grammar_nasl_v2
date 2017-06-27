#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-620. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16073);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/18 00:15:57 $");

  script_cve_id("CVE-2004-0452", "CVE-2004-0976");
  script_osvdb_id(11201, 12588);
  script_xref(name:"DSA", value:"620");

  script_name(english:"Debian DSA-620-1 : perl - insecure temporary files / directories");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Perl, the popular
scripting language. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CAN-2004-0452
    Jeroen van Wolffelaar discovered that the rmtree()
    function in the File::Path module removes directory
    trees in an insecure manner which could lead to the
    removal of arbitrary files and directories through a
    symlink attack.

  - CAN-2004-0976

    Trustix developers discovered several insecure uses of
    temporary files in many modules which allow a local
    attacker to overwrite files via a symlink attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-620"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the perl packages.

For the stable distribution (woody) these problems have been fixed in
version 5.6.1-8.8."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/02");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/30");
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
if (deb_check(release:"3.0", prefix:"libcgi-fast-perl", reference:"5.6.1-8.8")) flag++;
if (deb_check(release:"3.0", prefix:"libperl-dev", reference:"5.6.1-8.8")) flag++;
if (deb_check(release:"3.0", prefix:"libperl5.6", reference:"5.6.1-8.8")) flag++;
if (deb_check(release:"3.0", prefix:"perl", reference:"5.6.1-8.8")) flag++;
if (deb_check(release:"3.0", prefix:"perl-base", reference:"5.6.1-8.8")) flag++;
if (deb_check(release:"3.0", prefix:"perl-debug", reference:"5.6.1-8.8")) flag++;
if (deb_check(release:"3.0", prefix:"perl-doc", reference:"5.6.1-8.8")) flag++;
if (deb_check(release:"3.0", prefix:"perl-modules", reference:"5.6.1-8.8")) flag++;
if (deb_check(release:"3.0", prefix:"perl-suid", reference:"5.6.1-8.8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
