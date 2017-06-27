#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1992. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44856);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2010-0292", "CVE-2010-0293", "CVE-2010-0294");
  script_osvdb_id(62141, 62142, 62143);
  script_xref(name:"DSA", value:"1992");

  script_name(english:"Debian DSA-1992-1 : chrony - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in chrony, a pair of
programs which are used to maintain the accuracy of the system clock
on a computer. This issues are similar to the NTP security flaw
CVE-2009-3563. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2010-0292
    chronyd replies to all cmdmon packets with NOHOSTACCESS
    messages even for unauthorized hosts. An attacker can
    abuse this behaviour to force two chronyd instances to
    play packet ping-pong by sending such a packet with
    spoofed source address and port. This results in high
    CPU and network usage and thus denial of service
    conditions.

  - CVE-2010-0293
    The client logging facility of chronyd doesn't limit
    memory that is used to store client information. An
    attacker can cause chronyd to allocate large amounts of
    memory by sending NTP or cmdmon packets with spoofed
    source addresses resulting in memory exhaustion.

  - CVE-2010-0294
    chronyd lacks of a rate limit control to the syslog
    facility when logging received packets from unauthorized
    hosts. This allows an attacker to cause denial of
    service conditions via filling up the logs and thus disk
    space by repeatedly sending invalid cmdmon packets."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3563"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0294"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-1992"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chrony packages.

For the oldstable distribution (etch), this problem has been fixed in
version 1.21z-5+etch1.

For the stable distribution (lenny), this problem has been fixed in
version 1.23-6+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(20, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chrony");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"chrony", reference:"1.21z-5+etch1")) flag++;
if (deb_check(release:"5.0", prefix:"chrony", reference:"1.23-6+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
