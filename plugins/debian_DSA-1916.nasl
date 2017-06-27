#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1916. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44781);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:49:56 $");

  script_cve_id("CVE-2009-2702");
  script_bugtraq_id(36229);
  script_xref(name:"DSA", value:"1916");

  script_name(english:"Debian DSA-1916-1 : kdelibs - insufficient input validation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Dan Kaminsky and Moxie Marlinspike discovered that kdelibs, core
libraries from the official KDE release, does not properly handle a
'\0' character in a domain name in the Subject Alternative Name field
of an X.509 certificate, which allows man-in-the-middle attackers to
spoof arbitrary SSL servers via a crafted certificate issued by a
legitimate Certification Authority."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=546212"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1916"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kdelibs packages.

For the oldstable distribution (etch), this problem has been fixed in
version 4:3.5.5a.dfsg.1-8etch3.

Due to a bug in the archive system, the fix for the stable
distribution (lenny), will be released as version
4:3.5.10.dfsg.1-0lenny3 once it is available."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"kdelibs", reference:"4:3.5.5a.dfsg.1-8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kdelibs-data", reference:"4:3.5.5a.dfsg.1-8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kdelibs-dbg", reference:"4:3.5.5a.dfsg.1-8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kdelibs4-dev", reference:"4:3.5.5a.dfsg.1-8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kdelibs4-doc", reference:"4:3.5.5a.dfsg.1-8etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kdelibs4c2a", reference:"4:3.5.5a.dfsg.1-8etch3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
