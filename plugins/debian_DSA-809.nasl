#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-809. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19684);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/26 16:04:30 $");

  script_cve_id("CVE-2005-2794", "CVE-2005-2796");
  script_osvdb_id(19151, 19237);
  script_xref(name:"DSA", value:"809");

  script_name(english:"Debian DSA-809-2 : squid - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Certain aborted requests that trigger an assertion in squid, the
popular WWW proxy cache, may allow remote attackers to cause a denial
of service.  This update also fixes a regression caused by DSA 751.
For completeness below is the original advisory text :

  Several vulnerabilities have been discovered in Squid, the popular
  WWW proxy cache. The Common Vulnerabilities and Exposures project
  identifies the following problems :

    - CAN-2005-2794
      Certain aborted requests that trigger an assert may
      allow remote attackers to cause a denial of service.

    - CAN-2005-2796

      Specially crafted requests can cause a denial of
      service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=320035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-809"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the squid package.

For the oldstable distribution (woody) this problem has been fixed in
version 2.4.6-2woody10.

For the stable distribution (sarge) these problems have been fixed in
version 2.5.9-10sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"squid", reference:"2.4.6-2woody10")) flag++;
if (deb_check(release:"3.0", prefix:"squid-cgi", reference:"2.4.6-2woody10")) flag++;
if (deb_check(release:"3.0", prefix:"squidclient", reference:"2.4.6-2woody10")) flag++;
if (deb_check(release:"3.1", prefix:"squid", reference:"2.5.9-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"squid-cgi", reference:"2.5.9-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"squid-common", reference:"2.5.9-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"squidclient", reference:"2.5.9-10sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
