#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2558. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62453);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:37:39 $");

  script_cve_id("CVE-2012-4430");
  script_bugtraq_id(55505);
  script_osvdb_id(85494);
  script_xref(name:"DSA", value:"2558");

  script_name(english:"Debian DSA-2558-1 : bacula - information disclosure");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that bacula, a network backup service, does not
properly enforce console ACLs. This could allow information about
resources to be dumped by an otherwise-restricted client."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/bacula"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2558"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bacula packages.

For the stable distribution (squeeze), this problem has been fixed in
version 5.0.2-2.2+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bacula");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"bacula", reference:"5.0.2-2.2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"bacula-client", reference:"5.0.2-2.2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"bacula-common", reference:"5.0.2-2.2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"bacula-common-mysql", reference:"5.0.2-2.2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"bacula-common-pgsql", reference:"5.0.2-2.2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"bacula-common-sqlite3", reference:"5.0.2-2.2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"bacula-console", reference:"5.0.2-2.2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"bacula-console-qt", reference:"5.0.2-2.2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"bacula-director-common", reference:"5.0.2-2.2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"bacula-director-mysql", reference:"5.0.2-2.2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"bacula-director-pgsql", reference:"5.0.2-2.2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"bacula-director-sqlite", reference:"5.0.2-2.2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"bacula-director-sqlite3", reference:"5.0.2-2.2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"bacula-fd", reference:"5.0.2-2.2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"bacula-sd", reference:"5.0.2-2.2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"bacula-sd-mysql", reference:"5.0.2-2.2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"bacula-sd-pgsql", reference:"5.0.2-2.2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"bacula-sd-sqlite", reference:"5.0.2-2.2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"bacula-sd-sqlite3", reference:"5.0.2-2.2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"bacula-server", reference:"5.0.2-2.2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"bacula-traymonitor", reference:"5.0.2-2.2+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
