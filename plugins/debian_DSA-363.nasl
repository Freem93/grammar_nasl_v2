#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-363. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15200);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/05/18 00:11:34 $");

  script_cve_id("CVE-2003-0468", "CVE-2003-0540");
  script_osvdb_id(6551);
  script_xref(name:"DSA", value:"363");

  script_name(english:"Debian DSA-363-1 : postfix - denial of service, bounce-scanning");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The postfix mail transport agent in Debian 3.0 contains two
vulnerabilities :

  - CAN-2003-0468: Postfix would allow an attacker to
    bounce-scan private networks or use the daemon as a DDoS
    tool by forcing the daemon to connect to an arbitrary
    service at an arbitrary IP address and either receiving
    a bounce message or observing queue operations to infer
    the status of the delivery attempt.
  - CAN-2003-0540: a malformed envelope address can 1) cause
    the queue manager to lock up until an entry is removed
    from the queue and 2) lock up the smtp listener leading
    to a denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-363"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the current stable distribution (woody) these problems have been
fixed in version 1.1.11-0.woody3.


We recommend that you update your postfix package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postfix");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/08/03");
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
if (deb_check(release:"3.0", prefix:"postfix", reference:"1.1.11-0.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"postfix-dev", reference:"1.1.11-0.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"postfix-doc", reference:"1.1.11-0.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"postfix-ldap", reference:"1.1.11-0.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"postfix-mysql", reference:"1.1.11-0.woody3")) flag++;
if (deb_check(release:"3.0", prefix:"postfix-pcre", reference:"1.1.11-0.woody3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
