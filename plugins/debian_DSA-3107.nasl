#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3107. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80207);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/08/24 13:49:14 $");

  script_cve_id("CVE-2014-3580");
  script_bugtraq_id(71726);
  script_osvdb_id(115922);
  script_xref(name:"DSA", value:"3107");

  script_name(english:"Debian DSA-3107-1 : subversion - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Evgeny Kotkov discovered a NULL pointer dereference while processing
REPORT requests in mod_dav_svn, the Subversion component which is used
to serve repositories with the Apache web server. A remote attacker
could abuse this vulnerability for a denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=773263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/subversion"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-3107"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the subversion packages.

For the stable distribution (wheezy), this problem has been fixed in
version 1.6.17dfsg-4+deb7u7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libapache2-svn", reference:"1.6.17dfsg-4+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn-dev", reference:"1.6.17dfsg-4+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn-doc", reference:"1.6.17dfsg-4+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn-java", reference:"1.6.17dfsg-4+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn-perl", reference:"1.6.17dfsg-4+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn-ruby", reference:"1.6.17dfsg-4+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn-ruby1.8", reference:"1.6.17dfsg-4+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libsvn1", reference:"1.6.17dfsg-4+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"python-subversion", reference:"1.6.17dfsg-4+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"subversion", reference:"1.6.17dfsg-4+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"subversion-tools", reference:"1.6.17dfsg-4+deb7u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
