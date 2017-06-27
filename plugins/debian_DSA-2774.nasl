#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2774. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70374);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/16 15:43:09 $");

  script_cve_id("CVE-2013-4351", "CVE-2013-4402");
  script_osvdb_id(97339, 98164);
  script_xref(name:"DSA", value:"2774");

  script_name(english:"Debian DSA-2774-1 : gnupg2 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were discovered in GnuPG 2, the GNU privacy guard,
a free PGP replacement. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2013-4351
    When a key or subkey had its 'key flags' subpacket set
    to all bits off, GnuPG currently would treat the key as
    having all bits set. That is, where the owner wanted to
    indicate 'no use permitted', GnuPG would interpret it as
    'all use permitted'. Such 'no use permitted' keys are
    rare and only used in very special circumstances.

  - CVE-2013-4402
    Infinite recursion in the compressed packet parser was
    possible with crafted input data, which may be used to
    cause a denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=722724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=725433"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4351"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4402"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/gnupg2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/gnupg2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2774"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gnupg2 packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 2.0.14-2+squeeze2.

For the stable distribution (wheezy), these problems have been fixed
in version 2.0.19-2+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnupg2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/11");
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
if (deb_check(release:"6.0", prefix:"gnupg-agent", reference:"2.0.14-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gnupg2", reference:"2.0.14-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"gpgsm", reference:"2.0.14-2+squeeze2")) flag++;
if (deb_check(release:"7.0", prefix:"gnupg-agent", reference:"2.0.19-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"gnupg2", reference:"2.0.19-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"gpgsm", reference:"2.0.19-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"scdaemon", reference:"2.0.19-2+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
