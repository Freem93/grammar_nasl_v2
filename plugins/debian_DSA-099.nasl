#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-099. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14936);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/26 15:53:37 $");

  script_cve_id("CVE-2002-0006");
  script_xref(name:"DSA", value:"099");

  script_name(english:"Debian DSA-099-1 : xchat - IRC session hijacking");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"zen-parse found a vulnerability in the XChat IRC client that allows an
attacker to take over the users IRC session.

It is possible to trick XChat IRC clients into sending arbitrary
commands to the IRC server they are on, potentially allowing social
engineering attacks, channel takeovers, and denial of service. This
problem exists in versions 1.4.2 and 1.4.3. Later versions of XChat
are vulnerable as well, but this behaviour is controlled by the
configuration variable >>percascii<<, which defaults to 0. If it is
set to 1 then the problem becomes apparent in 1.6/1.8 as well."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://online.securityfocus.com/archive/1/249113"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-099"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"This problem has been fixed in upstream version 1.8.7 and in version
1.4.3-1 for the current stable Debian release (2.2) with a patch
provided from the upstream author Peter Zelezny. We recommend that you
upgrade your XChat packages immediately, since this problem is already
actively being exploited."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:XChat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"xchat", reference:"1.4.3-1")) flag++;
if (deb_check(release:"2.2", prefix:"xchat-common", reference:"1.4.3-1")) flag++;
if (deb_check(release:"2.2", prefix:"xchat-gnome", reference:"1.4.3-1")) flag++;
if (deb_check(release:"2.2", prefix:"xchat-text", reference:"1.4.3-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
