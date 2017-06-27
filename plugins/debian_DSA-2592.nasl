#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2592. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63342);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/16 15:37:39 $");

  script_cve_id("CVE-2012-4545");
  script_osvdb_id(88810);
  script_xref(name:"DSA", value:"2592");

  script_name(english:"Debian DSA-2592-1 : elinks - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Marko Myllynen discovered that ELinks, a powerful text-mode browser,
incorrectly delegates user credentials during GSS-Negotiate."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/elinks"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2592"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the elinks packages.

For the stable distribution (squeeze), this problem has been fixed in
version 0.12~pre5-2+squeeze1. Since the initial Squeeze release,
XULRunner needed to be updated and the version currently in the
archive is incompatible with ELinks. As such, JavaScript support
needed to be disabled (only a small subset of typical functionality
was supported anyway). It will likely be re-enabled in a later point
update."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:elinks");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"elinks", reference:"0.12~pre5-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"elinks-data", reference:"0.12~pre5-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"elinks-doc", reference:"0.12~pre5-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"elinks-lite", reference:"0.12~pre5-2+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
