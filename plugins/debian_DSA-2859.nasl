#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2859. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72439);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/16 15:43:10 $");

  script_cve_id("CVE-2013-6477", "CVE-2013-6478", "CVE-2013-6479", "CVE-2013-6481", "CVE-2013-6482", "CVE-2013-6483", "CVE-2013-6484", "CVE-2013-6485", "CVE-2013-6487", "CVE-2013-6489", "CVE-2013-6490", "CVE-2014-0020");
  script_bugtraq_id(65188, 65192, 65195, 65243);
  script_xref(name:"DSA", value:"2859");

  script_name(english:"Debian DSA-2859-1 : pidgin - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in Pidgin, a
multi-protocol instant messaging client :

  - CVE-2013-6477
    Jaime Breva Ribes discovered that a remote XMPP user can
    trigger a crash by sending a message with a timestamp in
    the distant future.

  - CVE-2013-6478
    Pidgin could be crashed through overly wide tooltip
    windows.

  - CVE-2013-6479
    Jacob Appelbaum discovered that a malicious server or a
    'man in the middle' could send a malformed HTTP header
    resulting in denial of service.

  - CVE-2013-6481
    Daniel Atallah discovered that Pidgin could be crashed
    through malformed Yahoo! P2P messages.

  - CVE-2013-6482
    Fabian Yamaguchi and Christian Wressnegger discovered
    that Pidgin could be crashed through malformed MSN
    messages.

  - CVE-2013-6483
    Fabian Yamaguchi and Christian Wressnegger discovered
    that Pidgin could be crashed through malformed XMPP
    messages.

  - CVE-2013-6484
    It was discovered that incorrect error handling when
    reading the response from a STUN server could result in
    a crash.

  - CVE-2013-6485
    Matt Jones discovered a buffer overflow in the parsing
    of malformed HTTP responses.

  - CVE-2013-6487
    Yves Younan and Ryan Pentney discovered a buffer
    overflow when parsing Gadu-Gadu messages.

  - CVE-2013-6489
    Yves Younan and Pawel Janic discovered an integer
    overflow when parsing MXit emoticons.

  - CVE-2013-6490
    Yves Younan discovered a buffer overflow when parsing
    SIMPLE headers.

  - CVE-2014-0020
    Daniel Atallah discovered that Pidgin could be crashed
    via malformed IRC arguments."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6479"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6481"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6482"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6487"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6490"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/pidgin"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2859"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the pidgin packages.

For the oldstable distribution (squeeze), no direct backport is
provided. A fixed package will be provided through
backports.debian.org shortly.

For the stable distribution (wheezy), these problems have been fixed
in version 2.10.9-1~deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"finch", reference:"2.10.9-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"finch-dev", reference:"2.10.9-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpurple-bin", reference:"2.10.9-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpurple-dev", reference:"2.10.9-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpurple0", reference:"2.10.9-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"pidgin", reference:"2.10.9-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"pidgin-data", reference:"2.10.9-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"pidgin-dbg", reference:"2.10.9-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"pidgin-dev", reference:"2.10.9-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
