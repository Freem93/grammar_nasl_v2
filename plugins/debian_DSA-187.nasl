#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-187. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15024);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/17 23:54:22 $");

  script_cve_id("CVE-2001-0131", "CVE-2002-0839", "CVE-2002-0840", "CVE-2002-0843", "CVE-2002-1233");
  script_bugtraq_id(2182, 5847, 5884, 5887, 5995);
  script_osvdb_id(862, 4552);
  script_xref(name:"DSA", value:"187");

  script_name(english:"Debian DSA-187-1 : apache - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"According to David Wagner, iDEFENSE and the Apache HTTP Server
Project, several remotely exploitable vulnerabilities have been found
in the Apache package, a commonly used webserver. These
vulnerabilities could allow an attacker to enact a denial of service
against a server or execute a cross scripting attack. The Common
Vulnerabilities and Exposures (CVE) project identified the following
vulnerabilities :

  - CAN-2002-0839: A vulnerability exists on platforms using
    System V shared memory based scoreboards. This
    vulnerability allows an attacker to execute code under
    the Apache UID to exploit the Apache shared memory
    scoreboard format and send a signal to any process as
    root or cause a local denial of service attack.
  - CAN-2002-0840: Apache is susceptible to a cross site
    scripting vulnerability in the default 404 page of any
    web server hosted on a domain that allows wildcard DNS
    lookups.

  - CAN-2002-0843: There were some possible overflows in the
    utility ApacheBench (ab) which could be exploited by a
    malicious server.

  - CAN-2002-1233: A race condition in the htpasswd and
    htdigest program enables a malicious local user to read
    or even modify the contents of a password file or easily
    create and overwrite files as the user running the
    htpasswd (or htdigest respectively) program.

  - CAN-2001-0131: htpasswd and htdigest in Apache 2.0a9,
    1.3.14, and others allows local users to overwrite
    arbitrary files via a symlink attack.

    This is the same vulnerability as CAN-2002-1233, which
    was fixed in potato already but got lost later and was
    never applied upstream.

  - NO-CAN: Several buffer overflows have been found in the
    ApacheBench (ab) utility that could be exploited by a
    remote server returning very long strings.
These problems have been fixed in version 1.3.26-0woody3 for the
current stable distribution (woody) and in 1.3.9-14.3 for the old
stable distribution (potato). Corrected packages for the unstable
distribution (sid) are expected soon."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-187"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the Apache package immediately."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/10/02");
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
if (deb_check(release:"2.2", prefix:"apache", reference:"1.3.9-14.3")) flag++;
if (deb_check(release:"2.2", prefix:"apache-common", reference:"1.3.9-14.3")) flag++;
if (deb_check(release:"2.2", prefix:"apache-dev", reference:"1.3.9-14.3")) flag++;
if (deb_check(release:"2.2", prefix:"apache-doc", reference:"1.3.9-14.3")) flag++;
if (deb_check(release:"3.0", prefix:"apache", reference:"1.3.26-0woody3")) flag++;
if (deb_check(release:"3.0", prefix:"apache-common", reference:"1.3.26-0woody3")) flag++;
if (deb_check(release:"3.0", prefix:"apache-dev", reference:"1.3.26-0woody3")) flag++;
if (deb_check(release:"3.0", prefix:"apache-doc", reference:"1.3.26-0woody3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
