#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2160. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51959);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/02/16 15:31:54 $");

  script_cve_id("CVE-2010-3718", "CVE-2011-0013", "CVE-2011-0534");
  script_bugtraq_id(46164, 46174, 46177);
  script_osvdb_id(70809, 71557, 71558);
  script_xref(name:"DSA", value:"2160");

  script_name(english:"Debian DSA-2160-1 : tomcat6 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in the Tomcat Servlet and JSP
engine :

  - CVE-2010-3718
    It was discovered that the SecurityManager
    insufficiently restricted the working directory.

  - CVE-2011-0013
    It was discovered that the HTML manager interface is
    affected by cross-site scripting.

  - CVE-2011-0534
    It was discovered that NIO connector performs
    insufficient validation of the HTTP headers, which could
    lead to denial of service.

The oldstable distribution (lenny) is not affected by these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=612257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3718"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0534"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/tomcat6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2160"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the tomcat6 packages.

For the stable distribution (squeeze), this problem has been fixed in
version 6.0.28-9+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libservlet2.5-java", reference:"6.0.28-9+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libservlet2.5-java-doc", reference:"6.0.28-9+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libtomcat6-java", reference:"6.0.28-9+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6", reference:"6.0.28-9+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-admin", reference:"6.0.28-9+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-common", reference:"6.0.28-9+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-docs", reference:"6.0.28-9+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-examples", reference:"6.0.28-9+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-user", reference:"6.0.28-9+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
