#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2578. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63068);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:37:39 $");

  script_cve_id("CVE-2012-2251", "CVE-2012-2252");
  script_osvdb_id(87926);
  script_xref(name:"DSA", value:"2578");

  script_name(english:"Debian DSA-2578-1 : rssh - insufficient filtering of rsync command line");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"James Clawson discovered that rssh, a restricted shell for OpenSSH to
be used with scp, sftp, rdist and cvs, was not correctly filtering
command line options. This could be used to force the execution of a
remote script and thus allow arbitrary command execution. Two CVE were
assigned :

  - CVE-2012-2251
    Incorrect filtering of command line when using rsync
    protocol. It was for example possible to pass dangerous
    options after a '--' switch. The rsync protocol support
    has been added in a Debian (and Fedora/Red Hat) specific
    patch, so this vulnerability doesn't affect upstream.

  - CVE-2012-2252
    Incorrect filtering of the '--rsh' option: the filter
    preventing usage of the'--rsh=' option would not prevent
    passing '--rsh'. This vulnerability affects upstream
    code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-2251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-2252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/rssh"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2578"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the rssh packages.

For the stable distribution (squeeze), this problem has been fixed in
version 2.3.2-13squeeze3."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rssh");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/28");
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
if (deb_check(release:"6.0", prefix:"rssh", reference:"2.3.2-13squeeze3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
