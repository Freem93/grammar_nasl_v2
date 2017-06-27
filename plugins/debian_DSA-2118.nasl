#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2118. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49815);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/12/17 11:41:45 $");

  script_cve_id("CVE-2010-3315");
  script_bugtraq_id(43678);
  script_xref(name:"DSA", value:"2118");

  script_name(english:"Debian DSA-2118-1 : subversion - logic flaw");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Kamesh Jayachandran and C. Michael Pilat discovered that the
mod_dav_svn module of Subversion, a version control system, is not
properly enforcing access rules which are scope-limited to named
repositories. If the SVNPathAuthz option is set to 'short_circuit' set
this may enable an unprivileged attacker to bypass intended access
restrictions and disclose or modify repository content."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2118"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the subversion packages.

As a workaround it is also possible to set SVNPathAuthz to 'on' but be
advised that this can result in a performance decrease for large
repositories.

For the stable distribution (lenny), this problem has been fixed in
version 1.5.1dfsg1-5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/11");
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
if (deb_check(release:"5.0", prefix:"libapache2-svn", reference:"1.5.1dfsg1-5")) flag++;
if (deb_check(release:"5.0", prefix:"libsvn-dev", reference:"1.5.1dfsg1-5")) flag++;
if (deb_check(release:"5.0", prefix:"libsvn-doc", reference:"1.5.1dfsg1-5")) flag++;
if (deb_check(release:"5.0", prefix:"libsvn-java", reference:"1.5.1dfsg1-5")) flag++;
if (deb_check(release:"5.0", prefix:"libsvn-perl", reference:"1.5.1dfsg1-5")) flag++;
if (deb_check(release:"5.0", prefix:"libsvn-ruby", reference:"1.5.1dfsg1-5")) flag++;
if (deb_check(release:"5.0", prefix:"libsvn-ruby1.8", reference:"1.5.1dfsg1-5")) flag++;
if (deb_check(release:"5.0", prefix:"libsvn1", reference:"1.5.1dfsg1-5")) flag++;
if (deb_check(release:"5.0", prefix:"python-subversion", reference:"1.5.1dfsg1-5")) flag++;
if (deb_check(release:"5.0", prefix:"subversion", reference:"1.5.1dfsg1-5")) flag++;
if (deb_check(release:"5.0", prefix:"subversion-tools", reference:"1.5.1dfsg1-5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
