#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1399. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27629);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-1659", "CVE-2007-1660", "CVE-2007-1661", "CVE-2007-1662", "CVE-2007-4766", "CVE-2007-4767", "CVE-2007-4768");
  script_osvdb_id(40759, 40760, 40763, 40766);
  script_xref(name:"DSA", value:"1399");

  script_name(english:"Debian DSA-1399-1 : pcre3 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tavis Ormandy of the Google Security Team has discovered several
security issues in PCRE, the Perl-Compatible Regular Expression
library, which potentially allow attackers to execute arbitrary code
by compiling specially crafted regular expressions.

Version 7.0 of the PCRE library featured a major rewrite of the
regular expression compiler, and it was deemed infeasible to backport
the security fixes in version 7.3 to the versions in Debian's stable
and oldstable distributions (6.7 and 4.5, respectively). Therefore,
this update is based on version 7.4 (which includes the security bug
fixes of the 7.3 version, plus several regression fixes), with special
patches to improve the compatibility with the older versions. As a
result, extra care is necessary when applying this update.

The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2007-1659
    Unmatched \Q\E sequences with orphan \E codes can cause
    the compiled regex to become desynchronized, resulting
    in corrupt bytecode that may result in multiple
    exploitable conditions.

  - CVE-2007-1660
    Multiple forms of character classes had their sizes
    miscalculated on initial passes, resulting in too little
    memory being allocated.

  - CVE-2007-1661
    Multiple patterns of the form \X?\d or \P{L}?\d in
    non-UTF-8 mode could backtrack before the start of the
    string, possibly leaking information from the address
    space, or causing a crash by reading out of bounds.

  - CVE-2007-1662
    A number of routines can be fooled into reading past the
    end of a string looking for unmatched parentheses or
    brackets, resulting in a denial of service.

  - CVE-2007-4766
    Multiple integer overflows in the processing of escape
    sequences could result in heap overflows or out of
    bounds reads/writes.

  - CVE-2007-4767
    Multiple infinite loops and heap overflows were
    discovered in the handling of \P and \P{x} sequences,
    where the length of these non-standard operations was
    mishandled.

  - CVE-2007-4768
    Character classes containing a lone unicode sequence
    were incorrectly optimised, resulting in a heap
    overflow."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1399"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the old stable distribution (sarge), these problems have been
fixed in version 4.5+7.4-1.

For the stable distribution (etch), these problems have been fixed in
version 6.7+7.4-2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pcre3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libpcre3", reference:"4.5+7.4-1")) flag++;
if (deb_check(release:"3.1", prefix:"libpcre3-dev", reference:"4.5+7.4-1")) flag++;
if (deb_check(release:"3.1", prefix:"pcregrep", reference:"4.5+7.4-1")) flag++;
if (deb_check(release:"3.1", prefix:"pgrep", reference:"4.5+7.4-1")) flag++;
if (deb_check(release:"4.0", prefix:"libpcre3", reference:"6.7+7.4-2")) flag++;
if (deb_check(release:"4.0", prefix:"libpcre3-dev", reference:"6.7+7.4-2")) flag++;
if (deb_check(release:"4.0", prefix:"libpcrecpp0", reference:"6.7+7.4-2")) flag++;
if (deb_check(release:"4.0", prefix:"pcregrep", reference:"6.7+7.4-2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
