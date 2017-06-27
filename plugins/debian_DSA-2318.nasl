#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2318. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56409);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:31:56 $");

  script_cve_id("CVE-2011-3208", "CVE-2011-3372");
  script_bugtraq_id(49534, 49949);
  script_osvdb_id(75307, 76057);
  script_xref(name:"DSA", value:"2318");

  script_name(english:"Debian DSA-2318-1 : cyrus-imapd-2.2 - multiple vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues have been discovered in cyrus-imapd, a highly
scalable mail system designed for use in enterprise environments. The
Common Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2011-3208
    Coverity discovered a stack-based buffer overflow in the
    NNTP server implementation (nttpd) of cyrus-imapd. An
    attacker can exploit this flaw via several crafted NNTP
    commands to execute arbitrary code.

  - CVE-2011-3372
    Stefan Cornelius of Secunia Research discovered that the
    command processing of the NNTP server implementation
    (nttpd) of cyrus-imapd is not properly implementing
    access restrictions for certain commands and is not
    checking for a complete, successful authentication. An
    attacker can use this flaw to bypass access restrictions
    for some commands and, e.g. exploit CVE-2011-3208
    without proper authentication."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3208"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3208"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/cyrus-imapd-2.2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2318"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the cyrus-imapd-2.2 packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 2.2_2.2.13-14+lenny5.

For the stable distribution (squeeze), this problem has been fixed in
version 2.2_2.2.13-19+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-imapd-2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"cyrus-imapd-2.2", reference:"2.2_2.2.13-14+lenny5")) flag++;
if (deb_check(release:"6.0", prefix:"cyrus-admin-2.2", reference:"2.2_2.2.13-19+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"cyrus-clients-2.2", reference:"2.2_2.2.13-19+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"cyrus-common-2.2", reference:"2.2_2.2.13-19+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"cyrus-dev-2.2", reference:"2.2_2.2.13-19+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"cyrus-doc-2.2", reference:"2.2_2.2.13-19+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"cyrus-imapd-2.2", reference:"2.2_2.2.13-19+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"cyrus-murder-2.2", reference:"2.2_2.2.13-19+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"cyrus-nntpd-2.2", reference:"2.2_2.2.13-19+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"cyrus-pop3d-2.2", reference:"2.2_2.2.13-19+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libcyrus-imap-perl22", reference:"2.2_2.2.13-19+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
