#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1977. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44841);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2008-2316", "CVE-2009-3560", "CVE-2009-3720");
  script_bugtraq_id(30491, 36097, 37203);
  script_osvdb_id(47479, 59737, 60797);
  script_xref(name:"DSA", value:"1977");

  script_name(english:"Debian DSA-1977-1 : python2.4 python2.5 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jukka Taimisto, Tero Rontti and Rauli Kaksonen discovered that the
embedded Expat copy in the interpreter for the Python language, does
not properly process malformed or crafted XML files. (CVE-2009-3560
CVE-2009-3720 ) This vulnerability could allow an attacker to cause a
denial of service while parsing a malformed XML file.

In addition, this update fixes an integer overflow in the hashlib
module in python2.5. This vulnerability could allow an attacker to
defeat cryptographic digests. (CVE-2008-2316 ) It only affects the
oldstable distribution (etch)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=493797"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=560912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=560913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3560"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3720"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2316"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-1977"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the python packages.

For the oldstable distribution (etch), these problems have been fixed
in version 2.4.4-3+etch3 for python2.4 and version 2.5-5+etch2 for
python2.5.

For the stable distribution (lenny), these problems have been fixed in
version 2.4.6-1+lenny1 for python2.4 and version 2.5.2-15+lenny1 for
python2.5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.4 python2.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/25");
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
if (deb_check(release:"4.0", prefix:"idle-python2.4", reference:"2.4.4-3+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"idle-python2.5", reference:"2.5-5+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"python2.4", reference:"2.4.4-3+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"python2.4-dbg", reference:"2.4.4-3+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"python2.4-dev", reference:"2.4.4-3+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"python2.4-examples", reference:"2.4.4-3+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"python2.4-minimal", reference:"2.4.4-3+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"python2.5", reference:"2.5-5+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"python2.5-dbg", reference:"2.5-5+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"python2.5-dev", reference:"2.5-5+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"python2.5-examples", reference:"2.5-5+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"python2.5-minimal", reference:"2.5-5+etch2")) flag++;
if (deb_check(release:"5.0", prefix:"idle-python2.4", reference:"2.4.6-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"idle-python2.5", reference:"2.5.2-15+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"python2.4", reference:"2.4.6-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"python2.4-dbg", reference:"2.4.6-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"python2.4-dev", reference:"2.4.6-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"python2.4-examples", reference:"2.4.6-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"python2.4-minimal", reference:"2.4.6-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"python2.5", reference:"2.5.2-15+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"python2.5-dbg", reference:"2.5.2-15+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"python2.5-dev", reference:"2.5.2-15+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"python2.5-examples", reference:"2.5.2-15+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"python2.5-minimal", reference:"2.5.2-15+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
