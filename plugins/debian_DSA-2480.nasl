#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2480. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59758);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2011-2082", "CVE-2011-2083", "CVE-2011-2084", "CVE-2011-2085", "CVE-2011-4458", "CVE-2011-4459", "CVE-2011-4460");
  script_bugtraq_id(53660);
  script_osvdb_id(82129, 82130, 82133, 82134, 82135, 82136, 82140);
  script_xref(name:"DSA", value:"2480");

  script_name(english:"Debian DSA-2480-4 : request-tracker3.8 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Request Tracker, an issue
tracking system :

  - CVE-2011-2082
    The vulnerable-passwords scripts introduced for
    CVE-2011-0009 failed to correct the password hashes of
    disabled users.

  - CVE-2011-2083
    Several cross-site scripting issues have been
    discovered.

  - CVE-2011-2084
    Password hashes could be disclosed by privileged users.

  - CVE-2011-2085
    Several cross-site request forgery vulnerabilities have
    been found. If this update breaks your setup, you can
    restore the old behaviour by setting $RestrictReferrer
    to 0.

  - CVE-2011-4458
    The code to support variable envelope return paths
    allowed the execution of arbitrary code.

  - CVE-2011-4459
    Disabled groups were not fully accounted as disabled.

  - CVE-2011-4460
    SQL injection vulnerability, only exploitable by
    privileged users.

Please note that if you run request-tracker3.8 under the Apache web
server, you must stop and start Apache manually. The 'restart'
mechanism is not recommended, especially when using mod_perl."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=674924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=675369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2085"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/request-tracker3.8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2480"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the request-tracker3.8 packages.

For the stable distribution (squeeze), these problems have been fixed
in version 3.8.8-7+squeeze5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:request-tracker3.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"request-tracker3.8", reference:"3.8.8-7+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"rt3.8-apache2", reference:"3.8.8-7+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"rt3.8-clients", reference:"3.8.8-7+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"rt3.8-db-mysql", reference:"3.8.8-7+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"rt3.8-db-postgresql", reference:"3.8.8-7+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"rt3.8-db-sqlite", reference:"3.8.8-7+squeeze5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
