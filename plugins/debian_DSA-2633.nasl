#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2633. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64897);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/16 15:37:39 $");

  script_cve_id("CVE-2013-1423");
  script_bugtraq_id(58143);
  script_osvdb_id(90605);
  script_xref(name:"DSA", value:"2633");

  script_name(english:"Debian DSA-2633-1 : fusionforge - privilege escalation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Helmut Grohne discovered multiple privilege escalation flaws in
FusionForge, a web-based project-management and collaboration
software. Most of the vulnerabilities are related to the bad handling
of privileged operations on user-controlled files or directories."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/fusionforge"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2633"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the fusionforge packages.

For the stable distribution (squeeze), this problem has been fixed in
version 5.0.2-5+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusionforge");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"fusionforge-full", reference:"5.0.2-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"fusionforge-minimal", reference:"5.0.2-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"fusionforge-standard", reference:"5.0.2-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gforge", reference:"5.0.2-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gforge-common", reference:"5.0.2-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gforge-db-postgresql", reference:"5.0.2-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gforge-dns-bind9", reference:"5.0.2-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gforge-ftp-proftpd", reference:"5.0.2-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gforge-lists-mailman", reference:"5.0.2-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gforge-mta-courier", reference:"5.0.2-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gforge-mta-exim4", reference:"5.0.2-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gforge-mta-postfix", reference:"5.0.2-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gforge-plugin-contribtracker", reference:"5.0.2-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gforge-plugin-extratabs", reference:"5.0.2-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gforge-plugin-globalsearch", reference:"5.0.2-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gforge-plugin-mediawiki", reference:"5.0.2-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gforge-plugin-projectlabels", reference:"5.0.2-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gforge-plugin-scmarch", reference:"5.0.2-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gforge-plugin-scmbzr", reference:"5.0.2-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gforge-plugin-scmcvs", reference:"5.0.2-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gforge-plugin-scmdarcs", reference:"5.0.2-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gforge-plugin-scmgit", reference:"5.0.2-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gforge-plugin-scmhg", reference:"5.0.2-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gforge-plugin-scmsvn", reference:"5.0.2-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gforge-shell-postgresql", reference:"5.0.2-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gforge-web-apache", reference:"5.0.2-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gforge-web-apache2", reference:"5.0.2-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gforge-web-apache2-vhosts", reference:"5.0.2-5+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
