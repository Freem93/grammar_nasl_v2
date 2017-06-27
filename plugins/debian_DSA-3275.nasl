#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3275. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83908);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/06/04 13:39:49 $");

  script_cve_id("CVE-2015-0850");
  script_xref(name:"DSA", value:"3275");

  script_name(english:"Debian DSA-3275-1 : fusionforge - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ansgar Burchardt discovered that the Git plugin for FusionForge, a
web-based project-management and collaboration software, does not
sufficiently validate user provided input as parameter to the method
to create secondary Git repositories. A remote attacker can use this
flaw to execute arbitrary code as root via a specially crafted URL."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/fusionforge"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3275"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the fusionforge packages.

For the stable distribution (jessie), this problem has been fixed in
version 5.3.2+20141104-3+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusionforge");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"fusionforge-full", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-minimal", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-plugin-admssw", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-plugin-authcas", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-plugin-authhttpd", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-plugin-authldap", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-plugin-blocks", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-plugin-compactpreview", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-plugin-contribtracker", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-plugin-doaprdf", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-plugin-extsubproj", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-plugin-foafprofiles", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-plugin-globalsearch", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-plugin-gravatar", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-plugin-headermenu", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-plugin-hudson", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-plugin-mediawiki", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-plugin-message", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-plugin-moinmoin", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-plugin-projectlabels", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-plugin-scmarch", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-plugin-scmbzr", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-plugin-scmcvs", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-plugin-scmdarcs", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-plugin-scmgit", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-plugin-scmhg", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-plugin-scmhook", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-plugin-scmsvn", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-plugin-sysauthldap", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fusionforge-standard", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gforge", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gforge-common", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gforge-db-postgresql", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gforge-db-remote", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gforge-dns-bind9", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gforge-ftp-proftpd", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gforge-lists-mailman", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gforge-mta-exim4", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gforge-mta-postfix", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gforge-shell-postgresql", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gforge-web-apache2", reference:"5.3.2+20141104-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gforge-web-apache2-vhosts", reference:"5.3.2+20141104-3+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
