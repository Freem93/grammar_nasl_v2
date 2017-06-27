#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1488. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30227);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/05/03 11:14:59 $");

  script_cve_id("CVE-2006-4758", "CVE-2006-6508", "CVE-2006-6839", "CVE-2006-6840", "CVE-2006-6841", "CVE-2008-0471");
  script_osvdb_id(35451);
  script_xref(name:"DSA", value:"1488");

  script_name(english:"Debian DSA-1488-1 : phpbb2 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in phpBB, a
web-based bulletin board. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2008-0471
    Private messaging allowed cross site request forgery,
    making it possible to delete all private messages of a
    user by sending them to a crafted web page.

  - CVE-2006-6841 / CVE-2006-6508
    Cross site request forgery enabled an attacker to
    perform various actions on behalf of a logged in user.
    (Applies to sarge only.)

  - CVE-2006-6840
    A negative start parameter could allow an attacker to
    create invalid output. (Applies to sarge only.)

  - CVE-2006-6839
    Redirection targets were not fully checked, leaving room
    for unauthorised external redirections via a phpBB
    forum. (Applies to sarge only.)

  - CVE-2006-4758
    An authenticated forum administrator may upload files of
    any type by using specially crafted filenames. (Applies
    to sarge only.)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=388120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=405980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=463589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6508"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1488"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the phpbb2 package.

For the old stable distribution (sarge), these problems have been
fixed in version 2.0.13+1-6sarge4.

For the stable distribution (etch), these problems have been fixed in
version 2.0.21-7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:phpbb2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/11");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/08");
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
if (deb_check(release:"3.1", prefix:"phpbb2", reference:"2.0.13-6sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"phpbb2-conf-mysql", reference:"2.0.13-6sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"phpbb2-languages", reference:"2.0.13-6sarge4")) flag++;
if (deb_check(release:"4.0", prefix:"phpbb2", reference:"2.0.21-7")) flag++;
if (deb_check(release:"4.0", prefix:"phpbb2-conf-mysql", reference:"2.0.21-7")) flag++;
if (deb_check(release:"4.0", prefix:"phpbb2-languages", reference:"2.0.21-7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
