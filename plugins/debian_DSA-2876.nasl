#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2876. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72991);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/16 15:43:10 $");

  script_cve_id("CVE-2013-6474", "CVE-2013-6475", "CVE-2013-6476");
  script_osvdb_id(104405, 104406, 104407);
  script_xref(name:"DSA", value:"2876");

  script_name(english:"Debian DSA-2876-1 : cups - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Florian Weimer of the Red Hat Product Security Team discovered
multiple vulnerabilities in the pdftoopvp CUPS filter, which could
result in the execution of aribitrary code if a malformed PDF file is
processed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/cups"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2876"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the cups packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 1.4.4-7+squeeze4.

For the stable distribution (wheezy) and the unstable distribution
(sid) the filter is now part of the cups-filters source package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/14");
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
if (deb_check(release:"6.0", prefix:"cups", reference:"1.4.4-7+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"cups-bsd", reference:"1.4.4-7+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"cups-client", reference:"1.4.4-7+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"cups-common", reference:"1.4.4-7+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"cups-dbg", reference:"1.4.4-7+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"cups-ppdc", reference:"1.4.4-7+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"cupsddk", reference:"1.4.4-7+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libcups2", reference:"1.4.4-7+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libcups2-dev", reference:"1.4.4-7+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libcupscgi1", reference:"1.4.4-7+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libcupscgi1-dev", reference:"1.4.4-7+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsdriver1", reference:"1.4.4-7+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsdriver1-dev", reference:"1.4.4-7+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsimage2", reference:"1.4.4-7+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsimage2-dev", reference:"1.4.4-7+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsmime1", reference:"1.4.4-7+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsmime1-dev", reference:"1.4.4-7+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsppdc1", reference:"1.4.4-7+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsppdc1-dev", reference:"1.4.4-7+squeeze4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
