#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-489-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91325);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/05/27 14:13:21 $");

  script_name(english:"Debian DLA-489-1 : ruby-mail security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This security update fixes a security issue in ruby-mail. We recommend
you upgrade your ruby-mail package.

Takeshi Terada (Mitsui Bussan Secure Directions, Inc.) released a
whitepaper entitled 'SMTP Injection via recipient email addresses' (
http://www.mbsd.jp/Whitepaper/smtpi.pdf). This whitepaper has a
section discussing how one such vulnerability affected the 'mail' ruby
gem (see section 3.1).

Whitepaper has all the specific details, but basically the
'mail' ruby gem module is prone to the recipient attack as
it does not validate nor sanitize given recipient addresses.
Thus, the attacks described in chapter 2 of the whitepaper
can be applied to the gem without any modification. The
'mail' ruby gem itself does not impose a length limit on
email addresses, so an attacker can send a long spam message
via a recipient address unless there is a limit on the
application's side. This vulnerability affects only the
applications that lack input validation.

For Debian 7 'Wheezy', these problems have been fixed in version
2.4.4-2+deb7u1.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mbsd.jp/Whitepaper/smtpi.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/05/msg00041.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/ruby-mail"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected ruby-mail package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-mail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"ruby-mail", reference:"2.4.4-2+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
