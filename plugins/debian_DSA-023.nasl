#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-023. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14860);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/17 23:36:50 $");

  script_cve_id("CVE-2001-0361");
  script_xref(name:"DSA", value:"023");

  script_name(english:"Debian DSA-023-1 : inn2 - local tempfile vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"- People at WireX have found several potential insecure
    uses of temporary files in programs provided by INN2.
    Some of them only lead to a vulnerability to symlink
    attacks if the temporary directory was set to /tmp or
    /var/tmp, which is the case in many installations, at
    least in Debian packages. An attacker could overwrite
    any file owned by the news system administrator, i.e.
    owned by news.news.
  - Michal Zalewski found an exploitable buffer overflow
    with regard to cancel messages and their verification.
    This bug did only show up if 'verifycancels' was enabled
    in inn.conf which is not the default and has been
    disrecommended by upstream.

  - Andi Kleen found a bug in INN2 that makes innd crash for
    two byte headers. There is a chance this can only be
    exploited with uucp."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2001/dsa-023"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the inn2 packages immediately."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inn2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
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
if (deb_check(release:"2.2", prefix:"inn2", reference:"2.2.2.2000.01.31-4.1")) flag++;
if (deb_check(release:"2.2", prefix:"inn2-dev", reference:"2.2.2.2000.01.31-4.1")) flag++;
if (deb_check(release:"2.2", prefix:"inn2-inews", reference:"2.2.2.2000.01.31-4.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
