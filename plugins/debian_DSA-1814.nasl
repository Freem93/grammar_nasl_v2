#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1814. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39374);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/05/03 11:20:10 $");

  script_cve_id("CVE-2009-1788", "CVE-2009-1791");
  script_bugtraq_id(34978);
  script_xref(name:"DSA", value:"1814");

  script_name(english:"Debian DSA-1814-1 : libsndfile - heap-based buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities have been found in libsndfile, a library to read
and write sampled audio data. The Common Vulnerabilities and Exposures
project identified the following problems :

  - CVE-2009-1788
    Tobias Klein discovered that the VOC parsing routines
    suffer of a heap-based buffer overflow which can be
    triggered by an attacker via a crafted VOC header.

  - CVE-2009-1791
    The vendor discovered that the AIFF parsing routines
    suffer of a heap-based buffer overflow similar to
    CVE-2009-1788 which can be triggered by an attacker via
    a crafted AIFF header.

In both cases the overflowing data is not completely attacker
controlled but still leads to application crashes or under some
circumstances might still lead to arbitrary code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=528650"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1791"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1814"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libsndfile packages.

For the oldstable distribution (etch), this problem has been fixed in
version 1.0.16-2+etch2.

For the stable distribution (lenny), this problem has been fixed in
version 1.0.17-4+lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsndfile");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libsndfile1", reference:"1.0.16-2+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libsndfile1-dev", reference:"1.0.16-2+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"sndfile-programs", reference:"1.0.16-2+etch2")) flag++;
if (deb_check(release:"5.0", prefix:"libsndfile1", reference:"1.0.17-4+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libsndfile1-dev", reference:"1.0.17-4+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"sndfile-programs", reference:"1.0.17-4+lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
