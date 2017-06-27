#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1637. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34212);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/06/05 10:49:46 $");

  script_cve_id("CVE-2008-3546");
  script_xref(name:"DSA", value:"1637");

  script_name(english:"Debian DSA-1637-1 : git-core - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been identified in git-core, the core of
the git distributed revision control system. Improper path length
limitations in git's diff and grep functions, in combination with
maliciously crafted repositories or changes, could enable a
stack-based buffer overflow and potentially the execution of arbitrary
code.

The Common Vulnerabilities and Exposures project identifies this
vulnerability as CVE-2008-3546."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=494097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1637"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the git-core packages.

For the stable distribution (etch), this problem has been fixed in
version 1.4.4.4-2.1+etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-core");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/16");
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
if (deb_check(release:"4.0", prefix:"git-arch", reference:"1.4.4.4-2.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"git-core", reference:"1.4.4.4-2.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"git-cvs", reference:"1.4.4.4-2.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"git-daemon-run", reference:"1.4.4.4-2.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"git-doc", reference:"1.4.4.4-2.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"git-email", reference:"1.4.4.4-2.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"git-svn", reference:"1.4.4.4-2.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"gitk", reference:"1.4.4.4-2.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"gitweb", reference:"1.4.4.4-2.1+etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");