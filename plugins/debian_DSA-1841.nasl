#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1841. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44706);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/05/17 23:54:22 $");

  script_cve_id("CVE-2009-2108");
  script_bugtraq_id(35338);
  script_osvdb_id(55034);
  script_xref(name:"DSA", value:"1841");

  script_name(english:"Debian DSA-1841-1 : git-core - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that git-daemon which is part of git-core, a popular
distributed revision control system, is vulnerable to denial of
service attacks caused by a programming mistake in handling requests
containing extra unrecognized arguments which results in an infinite
loop. While this is no problem for the daemon itself as every request
will spawn a new git-daemon instance, this still results in a very
high CPU consumption and might lead to denial of service conditions."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=532935"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1841"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the git-core packages.

For the oldstable distribution (etch), this problem has been fixed in
version 1.4.4.4-4+etch3.

For the stable distribution (lenny), this problem has been fixed in
version 1.5.6.5-3+lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:git-core");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"git-arch", reference:"1.4.4.4-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"git-core", reference:"1.4.4.4-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"git-cvs", reference:"1.4.4.4-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"git-daemon-run", reference:"1.4.4.4-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"git-doc", reference:"1.4.4.4-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"git-email", reference:"1.4.4.4-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"git-svn", reference:"1.4.4.4-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"gitk", reference:"1.4.4.4-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"gitweb", reference:"1.4.4.4-4+etch3")) flag++;
if (deb_check(release:"5.0", prefix:"git-arch", reference:"1.5.6.5-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"git-core", reference:"1.5.6.5-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"git-cvs", reference:"1.5.6.5-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"git-daemon-run", reference:"1.5.6.5-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"git-doc", reference:"1.5.6.5-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"git-email", reference:"1.5.6.5-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"git-gui", reference:"1.5.6.5-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"git-svn", reference:"1.5.6.5-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"gitk", reference:"1.5.6.5-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"gitweb", reference:"1.5.6.5-3+lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
