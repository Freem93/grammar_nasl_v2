#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1501. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31145);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/26 15:53:37 $");

  script_cve_id("CVE-2007-6418");
  script_osvdb_id(44138);
  script_xref(name:"DSA", value:"1501");

  script_name(english:"Debian DSA-1501-1 : dspam - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tobias Grutzmacher discovered that a Debian-provided CRON script in
dspam, a statistical spam filter, included a database password on the
command line. This allowed a local attacker to read the contents of
the dspam database, such as emails."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=448519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1501"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the dspam package.

The old stable distribution (sarge) does not contain the dspam
package.

For the stable distribution (etch), this problem has been fixed in
version 3.6.8-5etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dspam");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"dspam", reference:"3.6.8-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"dspam-doc", reference:"3.6.8-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"dspam-webfrontend", reference:"3.6.8-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libdspam7", reference:"3.6.8-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libdspam7-dev", reference:"3.6.8-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libdspam7-drv-db4", reference:"3.6.8-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libdspam7-drv-mysql", reference:"3.6.8-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libdspam7-drv-pgsql", reference:"3.6.8-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libdspam7-drv-sqlite3", reference:"3.6.8-5etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
