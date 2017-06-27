#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1708. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35425);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-5516", "CVE-2008-5517", "CVE-2008-5916");
  script_osvdb_id(53538, 53539);
  script_xref(name:"DSA", value:"1708");

  script_name(english:"Debian DSA-1708-1 : git-core - shell command injection");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that gitweb, the web interface for the Git version
control system, contained several vulnerabilities :

Remote attackers could use crafted requests to execute shell commands
on the web server, using the snapshot generation and pickaxe search
functionality (CVE-2008-5916 ).

Local users with write access to the configuration of a Git repository
served by gitweb could cause gitweb to execute arbitrary shell
commands with the permission of the web server (CVE-2008-5516,
CVE-2008-5517 )."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=512330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5916"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1708"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Git packages.

For the stable distribution (etch), these problems have been fixed in
version 1.4.4.4-4+etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(78, 94, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-core");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"git-arch", reference:"1.4.4.4-4+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"git-core", reference:"1.4.4.4-4+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"git-cvs", reference:"1.4.4.4-4+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"git-daemon-run", reference:"1.4.4.4-4+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"git-doc", reference:"1.4.4.4-4+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"git-email", reference:"1.4.4.4-4+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"git-svn", reference:"1.4.4.4-4+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"gitk", reference:"1.4.4.4-4+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"gitweb", reference:"1.4.4.4-4+etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
