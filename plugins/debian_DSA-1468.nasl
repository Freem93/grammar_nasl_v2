#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1468. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30060);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-2450", "CVE-2008-0128");
  script_bugtraq_id(24475);
  script_osvdb_id(40853);
  script_xref(name:"DSA", value:"1468");

  script_name(english:"Debian DSA-1468-1 : tomcat5.5 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in the Tomcat
servlet and JSP engine. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2008-0128
    Olaf Kock discovered that HTTPS encryption was
    insufficiently enforced for single-sign-on cookies,
    which could result in information disclosure.

  - CVE-2007-2450
    It was discovered that the Manager and Host Manager web
    applications performed insufficient input sanitising,
    which could lead to cross site scripting.

This update also adapts the tomcat5.5-webapps package to the tightened
JULI permissions introduced in the previous tomcat5.5 DSA. However, it
should be noted, that the tomcat5.5-webapps is for demonstration and
documentation purposes only and should not be used for production
systems."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0128"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1468"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the tomcat5.5 packages.

The old stable distribution (sarge) doesn't contain tomcat5.5.

For the stable distribution (etch), these problems have been fixed in
version 5.5.20-2etch2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libtomcat5.5-java", reference:"5.5.20-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"tomcat5.5", reference:"5.5.20-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"tomcat5.5-admin", reference:"5.5.20-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"tomcat5.5-webapps", reference:"5.5.20-2etch2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
