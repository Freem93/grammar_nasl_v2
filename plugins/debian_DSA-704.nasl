#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-704. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18009);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/18 00:15:58 $");

  script_cve_id("CVE-2005-0387", "CVE-2005-0388");
  script_xref(name:"DSA", value:"704");

  script_name(english:"Debian DSA-704-1 : remstats - tempfile, missing input sanitising");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jens Steube discovered several vulnerabilities in remstats, the remote
statistics system. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CAN-2005-0387
    When processing uptime data on the unix-server a
    temporary file is opened in an insecure fashion which
    could be used for a symlink attack to create or
    overwrite arbitrary files with the permissions of the
    remstats user.

  - CAN-2005-0388

    The remoteping service can be exploited to execute
    arbitrary commands due to missing input sanitising."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-704"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the remstats packages.

For the stable distribution (woody) these problems have been fixed in
version 1.00a4-8woody1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:remstats");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"remstats", reference:"1.00a4-8woody1")) flag++;
if (deb_check(release:"3.0", prefix:"remstats-bintools", reference:"1.00a4-8woody1")) flag++;
if (deb_check(release:"3.0", prefix:"remstats-doc", reference:"1.00a4-8woody1")) flag++;
if (deb_check(release:"3.0", prefix:"remstats-servers", reference:"1.00a4-8woody1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
