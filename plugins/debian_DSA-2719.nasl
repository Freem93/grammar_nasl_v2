#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2719. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67236);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:43:09 $");

  script_cve_id("CVE-2013-1788", "CVE-2013-1790");
  script_bugtraq_id(59364, 59366);
  script_osvdb_id(90728, 90730, 98575, 98576, 98577, 98578);
  script_xref(name:"DSA", value:"2719");

  script_name(english:"Debian DSA-2719-1 : poppler - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in the poppler PDF rendering
library.

  - CVE-2013-1788
    Multiple invalid memory access issues, which could
    potentially lead to arbitrary code execution if the user
    were tricked into opening a malformed PDF document.

  - CVE-2013-1790
    An uninitialized memory issue, which could potentially
    lead to arbitrary code execution if the user were
    tricked into opening a malformed PDF document."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=702071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1790"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/poppler"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2719"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the poppler packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 0.12.4-1.2+squeeze3.

For the stable (wheezy), testing (jessie), and unstable (sid)
distributions, these problems have been fixed in version 0.18.4-6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:poppler");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/11");
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
if (deb_check(release:"6.0", prefix:"libpoppler-dev", reference:"0.12.4-1.2+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libpoppler-glib-dev", reference:"0.12.4-1.2+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libpoppler-glib4", reference:"0.12.4-1.2+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libpoppler-qt-dev", reference:"0.12.4-1.2+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libpoppler-qt2", reference:"0.12.4-1.2+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libpoppler-qt4-3", reference:"0.12.4-1.2+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libpoppler-qt4-dev", reference:"0.12.4-1.2+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libpoppler5", reference:"0.12.4-1.2+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"poppler-dbg", reference:"0.12.4-1.2+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"poppler-utils", reference:"0.12.4-1.2+squeeze3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
