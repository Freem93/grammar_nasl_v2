#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1813. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39334);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/06 20:12:52 $");

  script_cve_id("CVE-2009-0547", "CVE-2009-0582", "CVE-2009-0587");
  script_bugtraq_id(33720, 34100, 34109);
  script_xref(name:"DSA", value:"1813");

  script_name(english:"Debian DSA-1813-1 : evolution-data-server - Several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been found in evolution-data-server, the
database backend server for the evolution groupware suite. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2009-0587
    It was discovered that evolution-data-server is prone to
    integer overflows triggered by large base64 strings.

  - CVE-2009-0547
    Joachim Breitner discovered that S/MIME signatures are
    not verified properly, which can lead to spoofing
    attacks.

  - CVE-2009-0582
    It was discovered that NTLM authentication challenge
    packets are not validated properly when using the NTLM
    authentication method, which could lead to an
    information disclosure or a denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=508479"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1813"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the evolution-data-server packages.

For the oldstable distribution (etch), these problems have been fixed
in version 1.6.3-5etch2.

For the stable distribution (lenny), these problems have been fixed in
version 2.22.3-1.1+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 189, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:evolution-data-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"evolution-data-server", reference:"1.6.3-5etch2")) flag++;
if (deb_check(release:"4.0", prefix:"evolution-data-server-common", reference:"1.6.3-5etch2")) flag++;
if (deb_check(release:"4.0", prefix:"evolution-data-server-dbg", reference:"1.6.3-5etch2")) flag++;
if (deb_check(release:"4.0", prefix:"evolution-data-server-dev", reference:"1.6.3-5etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libcamel1.2-8", reference:"1.6.3-5etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libcamel1.2-dev", reference:"1.6.3-5etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libebook1.2-5", reference:"1.6.3-5etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libebook1.2-dev", reference:"1.6.3-5etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libecal1.2-6", reference:"1.6.3-5etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libecal1.2-dev", reference:"1.6.3-5etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libedata-book1.2-2", reference:"1.6.3-5etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libedata-book1.2-dev", reference:"1.6.3-5etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libedata-cal1.2-5", reference:"1.6.3-5etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libedata-cal1.2-dev", reference:"1.6.3-5etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libedataserver1.2-7", reference:"1.6.3-5etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libedataserver1.2-dev", reference:"1.6.3-5etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libedataserverui1.2-6", reference:"1.6.3-5etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libedataserverui1.2-dev", reference:"1.6.3-5etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libegroupwise1.2-10", reference:"1.6.3-5etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libegroupwise1.2-dev", reference:"1.6.3-5etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libexchange-storage1.2-1", reference:"1.6.3-5etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libexchange-storage1.2-dev", reference:"1.6.3-5etch2")) flag++;
if (deb_check(release:"5.0", prefix:"evolution-data-server", reference:"2.22.3-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"evolution-data-server-common", reference:"2.22.3-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"evolution-data-server-dbg", reference:"2.22.3-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"evolution-data-server-dev", reference:"2.22.3-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libcamel1.2-11", reference:"2.22.3-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libcamel1.2-dev", reference:"2.22.3-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libebook1.2-9", reference:"2.22.3-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libebook1.2-dev", reference:"2.22.3-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libecal1.2-7", reference:"2.22.3-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libecal1.2-dev", reference:"2.22.3-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libedata-book1.2-2", reference:"2.22.3-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libedata-book1.2-dev", reference:"2.22.3-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libedata-cal1.2-6", reference:"2.22.3-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libedata-cal1.2-dev", reference:"2.22.3-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libedataserver1.2-9", reference:"2.22.3-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libedataserver1.2-dev", reference:"2.22.3-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libedataserverui1.2-8", reference:"2.22.3-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libedataserverui1.2-dev", reference:"2.22.3-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libegroupwise1.2-13", reference:"2.22.3-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libegroupwise1.2-dev", reference:"2.22.3-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libexchange-storage1.2-3", reference:"2.22.3-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libexchange-storage1.2-dev", reference:"2.22.3-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libgdata-google1.2-1", reference:"2.22.3-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libgdata-google1.2-dev", reference:"2.22.3-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libgdata1.2-1", reference:"2.22.3-1.1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libgdata1.2-dev", reference:"2.22.3-1.1+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
