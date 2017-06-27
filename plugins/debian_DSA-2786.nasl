#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2786. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70664);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/02/16 15:43:10 $");

  script_cve_id("CVE-2013-0900", "CVE-2013-2924");
  script_bugtraq_id(58318, 62968);
  script_osvdb_id(90542, 97966);
  script_xref(name:"DSA", value:"2786");

  script_name(english:"Debian DSA-2786-1 : icu - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Google Chrome Security Team discovered two issues (a race
condition and a use-after-free issue) in the International Components
for Unicode (ICU) library."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=702346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=726477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/icu"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/icu"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2786"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the icu packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 4.4.1-8+squeeze2.

For the stable distribution (wheezy), which is only affected by
CVE-2013-2924, this problem has been fixed in version
4.8.1.1-12+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"icu-doc", reference:"4.4.1-8+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"lib32icu-dev", reference:"4.4.1-8+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"lib32icu44", reference:"4.4.1-8+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libicu-dev", reference:"4.4.1-8+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libicu44", reference:"4.4.1-8+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libicu44-dbg", reference:"4.4.1-8+squeeze2")) flag++;
if (deb_check(release:"7.0", prefix:"icu-doc", reference:"4.8.1.1-12+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libicu-dev", reference:"4.8.1.1-12+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libicu48", reference:"4.8.1.1-12+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libicu48-dbg", reference:"4.8.1.1-12+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
