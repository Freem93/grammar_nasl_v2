#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-811. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19690);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/26 16:04:30 $");

  script_cve_id("CVE-2005-2657");
  script_osvdb_id(19385);
  script_xref(name:"DSA", value:"811");

  script_name(english:"Debian DSA-811-2 : common-lisp-controller - design error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The bugfix for the problem mentioned below contained an error that
caused third-party programs to fail.  The problem is corrected by
this update.  For completeness we're including the original advisory
text :

  Francois-Rene Rideau discovered a bug in common-lisp-controller, a
  Common Lisp source and compiler manager, that allows a local user to
  compile malicious code into a cache directory which is executed by
  another user if that user has not used Common Lisp before."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-811"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the common-lisp-controller package.

The old stable distribution (woody) is not affected by this problem.

For the stable distribution (sarge) this problem has been fixed in
version 4.15sarge3."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:common-lisp-controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"common-lisp-controller", reference:"4.15sarge3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
