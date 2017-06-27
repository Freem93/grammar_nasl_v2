#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2603. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63456);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:37:39 $");

  script_cve_id("CVE-2012-3479");
  script_bugtraq_id(54969);
  script_osvdb_id(84691);
  script_xref(name:"DSA", value:"2603");

  script_name(english:"Debian DSA-2603-1 : emacs23 - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Paul Ling discovered that Emacs insufficiently restricted the
evaluation of Lisp code if enable-local-variables is set to 'safe'."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/emacs23"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2603"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the emacs23 packages.

For the stable distribution (squeeze), this problem has been fixed in
version 23.2+1-7+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:emacs23");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/10");
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
if (deb_check(release:"6.0", prefix:"emacs", reference:"23.2+1-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"emacs23", reference:"23.2+1-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"emacs23-bin-common", reference:"23.2+1-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"emacs23-common", reference:"23.2+1-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"emacs23-el", reference:"23.2+1-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"emacs23-lucid", reference:"23.2+1-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"emacs23-nox", reference:"23.2+1-7+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
