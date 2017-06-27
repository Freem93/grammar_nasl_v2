#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-977. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22843);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/05/03 11:30:24 $");

  script_cve_id("CVE-2006-0582", "CVE-2006-0677");
  script_osvdb_id(22986, 23244);
  script_xref(name:"DSA", value:"977");

  script_name(english:"Debian DSA-977-1 : heimdal - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities have been discovered in heimdal, a free
implementation of Kerberos 5. The Common Vulnerabilities and Exposures
project identifies the following vulnerabilities :

  - CVE-2006-0582
    Privilege escalation in the rsh server allows an
    authenticated attacker to overwrite arbitrary files and
    gain ownership of them.

  - CVE-2006-0677
    A remote attacker could force the telnet server to crash
    before the user logged in, resulting in inetd turning
    telnetd off because it forked too fast.

The old stable distribution (woody) does not expose rsh and telnet
servers."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0677"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-977"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the heimdal packages.

For the stable distribution (sarge) these problems have been fixed in
version 0.6.3-10sarge2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"heimdal-clients", reference:"0.6.3-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"heimdal-clients-x", reference:"0.6.3-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"heimdal-dev", reference:"0.6.3-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"heimdal-docs", reference:"0.6.3-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"heimdal-kdc", reference:"0.6.3-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"heimdal-servers", reference:"0.6.3-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"heimdal-servers-x", reference:"0.6.3-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libasn1-6-heimdal", reference:"0.6.3-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libgssapi1-heimdal", reference:"0.6.3-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libhdb7-heimdal", reference:"0.6.3-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libkadm5clnt4-heimdal", reference:"0.6.3-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libkadm5srv7-heimdal", reference:"0.6.3-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libkafs0-heimdal", reference:"0.6.3-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libkrb5-17-heimdal", reference:"0.6.3-10sarge2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
