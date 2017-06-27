#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-042. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14879);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/06 20:12:49 $");

  script_bugtraq_id(2333);
  script_xref(name:"DSA", value:"042");

  script_name(english:"Debian DSA-042-1 : gnuserv");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Klaus Frank has found a vulnerability in the way gnuserv handled
remote connections. Gnuserv is a remote control facility for Emacsen
which is available as standalone program as well as included in
XEmacs21. Gnuserv has a buffer for which insufficient boundary checks
were made. Unfortunately this buffer affected access control to
gnuserv which is using a MIT-MAGIC-COOCKIE based system. It is
possible to overflow the buffer containing the cookie and foozle
cookie comparison.

Gnuserv was derived from emacsserver which is part of GNU Emacs. It
was reworked completely and not much is left over from its time as
part of GNU Emacs. Therefore the versions of emacsserver in both
Emacs19 and Emacs20 doesn't look vulnerable to this bug, they don't
even provide a MIT-MAGIC-COOKIE based mechanism.

This could lead into a remote user issue commands under the UID of the
person running gnuserv."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2001/dsa-042"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected gnuserv, and xemacs21 packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnuserv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xemacs21");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/03/09");
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
if (deb_check(release:"2.2", prefix:"gnuserv", reference:"2.1alpha-5.1")) flag++;
if (deb_check(release:"2.2", prefix:"xemacs21", reference:"21.1.10-5")) flag++;
if (deb_check(release:"2.2", prefix:"xemacs21-bin", reference:"21.1.10-5")) flag++;
if (deb_check(release:"2.2", prefix:"xemacs21-mule", reference:"21.1.10-5")) flag++;
if (deb_check(release:"2.2", prefix:"xemacs21-mule-canna-wnn", reference:"21.1.10-5")) flag++;
if (deb_check(release:"2.2", prefix:"xemacs21-nomule", reference:"21.1.10-5")) flag++;
if (deb_check(release:"2.2", prefix:"xemacs21-support", reference:"21.1.10-5")) flag++;
if (deb_check(release:"2.2", prefix:"xemacs21-supportel", reference:"21.1.10-5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
