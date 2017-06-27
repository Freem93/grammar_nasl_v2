#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3055. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78659);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/16 15:48:48 $");

  script_cve_id("CVE-2014-3694", "CVE-2014-3695", "CVE-2014-3696", "CVE-2014-3698");
  script_bugtraq_id(70701, 70702, 70703, 70705);
  script_xref(name:"DSA", value:"3055");

  script_name(english:"Debian DSA-3055-1 : pidgin - security update");
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

  - CVE-2014-3694
    It was discovered that the SSL/TLS plugins failed to
    validate the basic constraints extension in intermediate
    CA certificates.

  - CVE-2014-3695
    Yves Younan and Richard Johnson discovered that
    emoticons with overly large length values could crash
    Pidgin.

  - CVE-2014-3696
    Yves Younan and Richard Johnson discovered that
    malformed Groupwise messages could crash Pidgin.

  - CVE-2014-3698
    Thijs Alkemade and Paul Aurich discovered that malformed
    XMPP messages could result in memory disclosure."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/pidgin"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-3055"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the pidgin packages.

For the stable distribution (wheezy), these problems have been fixed
in version 2.10.10-1~deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/24");
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
if (deb_check(release:"7.0", prefix:"finch", reference:"2.10.10-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"finch-dev", reference:"2.10.10-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpurple-bin", reference:"2.10.10-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpurple-dev", reference:"2.10.10-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpurple0", reference:"2.10.10-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"pidgin", reference:"2.10.10-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"pidgin-data", reference:"2.10.10-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"pidgin-dbg", reference:"2.10.10-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"pidgin-dev", reference:"2.10.10-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
