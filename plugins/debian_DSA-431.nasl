#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-431. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15268);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2014/04/30 10:43:34 $");

  script_cve_id("CVE-2003-0618");
  script_bugtraq_id(9543);
  script_osvdb_id(6103);
  script_xref(name:"DSA", value:"431");

  script_name(english:"Debian DSA-431-1 : perl - information leak");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Paul Szabo discovered a number of similar bugs in suidperl, a helper
program to run perl scripts with setuid privileges. By exploiting
these bugs, an attacker could abuse suidperl to discover information
about files (such as testing for their existence and some of their
permissions) that should not be accessible to unprivileged users."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/220486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-431"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the current stable distribution (woody) this problem has been
fixed in version 5.6.1-8.6.

We recommend that you update your perl package if you have the
'perl-suid' package installed."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/08/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"libcgi-fast-perl", reference:"5.6.1-8.6")) flag++;
if (deb_check(release:"3.0", prefix:"libperl-dev", reference:"5.6.1-8.6")) flag++;
if (deb_check(release:"3.0", prefix:"libperl5.6", reference:"5.6.1-8.6")) flag++;
if (deb_check(release:"3.0", prefix:"perl", reference:"5.6.1-8.6")) flag++;
if (deb_check(release:"3.0", prefix:"perl-base", reference:"5.6.1-8.6")) flag++;
if (deb_check(release:"3.0", prefix:"perl-debug", reference:"5.6.1-8.6")) flag++;
if (deb_check(release:"3.0", prefix:"perl-doc", reference:"5.6.1-8.6")) flag++;
if (deb_check(release:"3.0", prefix:"perl-modules", reference:"5.6.1-8.6")) flag++;
if (deb_check(release:"3.0", prefix:"perl-suid", reference:"5.6.1-8.6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
