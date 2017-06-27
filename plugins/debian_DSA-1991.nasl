#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1991. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44855);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/05/03 11:20:11 $");

  script_cve_id("CVE-2009-2855", "CVE-2010-0308");
  script_bugtraq_id(36091, 37522);
  script_xref(name:"DSA", value:"1991");

  script_name(english:"Debian DSA-1991-1 : squid/squid3 - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two denial of service vulnerabilities have been discovered in squid
and squid3, a web proxy. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2009-2855
    Bastian Blank discovered that it is possible to cause a
    denial of service via a crafted auth header with certain
    comma delimiters.

  - CVE-2010-0308
    Tomas Hoger discovered that it is possible to cause a
    denial of service via invalid DNS header-only packets."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=534982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-1991"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the squid/squid3 packages.

For the stable distribution (lenny), these problems have been fixed in
version 2.7.STABLE3-4.1lenny1 of the squid package and version
3.0.STABLE8-3+lenny3 of the squid3 package.

For the oldstable distribution (etch), these problems have been fixed
in version 2.6.5-6etch5 of the squid package and version
3.0.PRE5-5+etch2 of the squid3 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"squid", reference:"2.6.5-6etch5")) flag++;
if (deb_check(release:"4.0", prefix:"squid-cgi", reference:"2.6.5-6etch5")) flag++;
if (deb_check(release:"4.0", prefix:"squid-common", reference:"2.6.5-6etch5")) flag++;
if (deb_check(release:"4.0", prefix:"squid3", reference:"3.0.PRE5-5+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"squid3-cgi", reference:"3.0.PRE5-5+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"squid3-client", reference:"3.0.PRE5-5+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"squid3-common", reference:"3.0.PRE5-5+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"squidclient", reference:"2.6.5-6etch5")) flag++;
if (deb_check(release:"5.0", prefix:"squid", reference:"2.7.STABLE3-4.1lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"squid-cgi", reference:"2.7.STABLE3-4.1lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"squid-common", reference:"2.7.STABLE3-4.1lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"squid3", reference:"3.0.STABLE8-3+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"squid3-cgi", reference:"3.0.STABLE8-3+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"squid3-common", reference:"3.0.STABLE8-3+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"squidclient", reference:"3.0.STABLE8-3+lenny3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
