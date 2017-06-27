#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-656. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16246);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2005-0071");
  script_osvdb_id(13174);
  script_xref(name:"DSA", value:"656");

  script_name(english:"Debian DSA-656-1 : vdr - insecure file access");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Javier Fernandez-Sanguino Pena from the Debian Security Audit Team
has discovered that the vdr daemon which is used for video disk
recorders for DVB cards can overwrite arbitrary files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-656"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the vdr package.

For the stable distribution (woody) this problem has been fixed in
version 1.0.0-1woody2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vdr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/25");
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
if (deb_check(release:"3.0", prefix:"vdr", reference:"1.0.0-1woody2")) flag++;
if (deb_check(release:"3.0", prefix:"vdr-daemon", reference:"1.0.0-1woody2")) flag++;
if (deb_check(release:"3.0", prefix:"vdr-kbd", reference:"1.0.0-1woody2")) flag++;
if (deb_check(release:"3.0", prefix:"vdr-lirc", reference:"1.0.0-1woody2")) flag++;
if (deb_check(release:"3.0", prefix:"vdr-rcu", reference:"1.0.0-1woody2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
