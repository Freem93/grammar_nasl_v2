#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-216. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15053);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/05/17 23:58:35 $");

  script_cve_id("CVE-2002-1365");
  script_bugtraq_id(6390);
  script_osvdb_id(4594);
  script_xref(name:"DSA", value:"216");

  script_name(english:"Debian DSA-216-1 : fetchmail - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Stefan Esser of e-matters discovered a buffer overflow in fetchmail,
an SSL enabled POP3, APOP and IMAP mail gatherer/forwarder. When
fetchmail retrieves a mail all headers that contain addresses are
searched for local addresses. If a hostname is missing, fetchmail
appends it but doesn't reserve enough space for it. This heap overflow
can be used by remote attackers to crash it or to execute arbitrary
code with the privileges of the user running fetchmail."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-216"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the fetchmail packages.

For the current stable distribution (woody) this problem has been
fixed in version 5.9.11-6.2 of fetchmail and fetchmail-ssl.

For the old stable distribution (potato) this problem has been fixed
in version 5.3.3-4.3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fetchmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/12/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/01/09");
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
if (deb_check(release:"2.2", prefix:"fetchmail", reference:"5.3.3-4.3")) flag++;
if (deb_check(release:"2.2", prefix:"fetchmailconf", reference:"5.3.3-4.3")) flag++;
if (deb_check(release:"3.0", prefix:"fetchmail", reference:"5.9.11-6.2")) flag++;
if (deb_check(release:"3.0", prefix:"fetchmail-common", reference:"5.9.11-6.2")) flag++;
if (deb_check(release:"3.0", prefix:"fetchmail-ssl", reference:"5.9.11-6.2")) flag++;
if (deb_check(release:"3.0", prefix:"fetchmailconf", reference:"5.9.11-6.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
