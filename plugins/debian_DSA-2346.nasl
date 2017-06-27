#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2346. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56850);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2011-4130");
  script_bugtraq_id(50631);
  script_osvdb_id(77004);
  script_xref(name:"DSA", value:"2346");

  script_name(english:"Debian DSA-2346-2 : proftpd-dfsg - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in ProFTPD, an FTP server :

  - (No CVE id)
    ProFTPD incorrectly uses data from an unencrypted input
    buffer after encryption has been enabled with STARTTLS,
    an issue similar to CVE-2011-0411.

  - CVE-2011-4130
    ProFTPD uses a response pool after freeing it under
    exceptional conditions, possibly leading to remote code
    execution. (The version in lenny is not affected by this
    problem.)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=648373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/proftpd-dfsg"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2346"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the proftpd-dfsg packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.3.1-17lenny9.

For the stable distribution (squeeze), this problem has been fixed in
version 1.3.3a-6squeeze4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-dfsg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"proftpd-dfsg", reference:"1.3.1-17lenny9")) flag++;
if (deb_check(release:"6.0", prefix:"proftpd-basic", reference:"1.3.3a-6squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"proftpd-dev", reference:"1.3.3a-6squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"proftpd-doc", reference:"1.3.3a-6squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"proftpd-mod-ldap", reference:"1.3.3a-6squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"proftpd-mod-mysql", reference:"1.3.3a-6squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"proftpd-mod-odbc", reference:"1.3.3a-6squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"proftpd-mod-pgsql", reference:"1.3.3a-6squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"proftpd-mod-sqlite", reference:"1.3.3a-6squeeze4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
