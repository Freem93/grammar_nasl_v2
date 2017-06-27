#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-097. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14934);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/17 23:36:51 $");

  script_osvdb_id(5330);
  script_xref(name:"DSA", value:"097");

  script_name(english:"Debian DSA-097-1 : exim - Uncontrolled program execution");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Patrice Fournier discovered a bug in all versions of Exim older than
Exim 3.34 and Exim 3.952.

The Exim maintainer, Philip Hazel, writes about this issue: 'The
problem exists only in the case of a run time configuration which
directs or routes an address to a pipe transport without checking the
local part of the address in any way. This does not apply, for
example, to pipes run from alias or forward files, because the local
part is checked to ensure that it is the name of an alias or of a
local user. The bug's effect is that, instead of obeying the correct
pipe command, a broken Exim runs the command encoded in the local part
of the address.'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.exim.org/pipermail/exim-announce/2001q4/000048.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-097"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"This problem has been fixed in Exim version 3.12-10.2 for the stable
distribution Debian GNU/Linux 2.2 and 3.33-1.1 for the testing and
unstable distribution. We recommend that you upgrade your exim
package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/02/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"exim", reference:"3.12-10.2")) flag++;
if (deb_check(release:"2.2", prefix:"eximon", reference:"3.12-10.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
