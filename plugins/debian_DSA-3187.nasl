#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3187. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81831);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/09/09 14:39:26 $");

  script_cve_id("CVE-2013-1569", "CVE-2013-2383", "CVE-2013-2384", "CVE-2013-2419", "CVE-2014-6585", "CVE-2014-6591", "CVE-2014-7923", "CVE-2014-7926", "CVE-2014-7940", "CVE-2014-9654");
  script_bugtraq_id(59131, 59166, 59179, 59190, 72173, 72175);
  script_osvdb_id(92335, 92336, 92337, 92342, 117232, 117233, 117380, 117383, 117397, 117639);
  script_xref(name:"DSA", value:"3187");

  script_name(english:"Debian DSA-3187-1 : icu - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in the International
Components for Unicode (ICU) library.

  - CVE-2013-1569
    Glyph table issue.

  - CVE-2013-2383
    Glyph table issue.

  - CVE-2013-2384
    Font layout issue.

  - CVE-2013-2419
    Font processing issue.

  - CVE-2014-6585
    Out-of-bounds read.

  - CVE-2014-6591
    Additional out-of-bounds reads.

  - CVE-2014-7923
    Memory corruption in regular expression comparison.

  - CVE-2014-7926
    Memory corruption in regular expression comparison.

  - CVE-2014-7940
    Uninitialized memory.

  - CVE-2014-9654
    More regular expression flaws."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=775884"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=776264"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=776265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=776719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1569"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2383"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-6585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-6591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-7923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-7926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-7940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/icu"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3187"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the icu packages.

For the stable distribution (wheezy), these problems have been fixed
in version 4.8.1.1-12+deb7u2.

For the upcoming stable (jessie) and unstable (sid) distributions,
these problems have been fixed in version 52.1-7.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"icu-doc", reference:"4.8.1.1-12+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libicu-dev", reference:"4.8.1.1-12+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libicu48", reference:"4.8.1.1-12+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libicu48-dbg", reference:"4.8.1.1-12+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
