#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-900. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22766);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/26 16:04:30 $");

  script_cve_id("CVE-2005-3088");
  script_bugtraq_id(15179);
  script_osvdb_id(20267);
  script_xref(name:"DSA", value:"900");

  script_name(english:"Debian DSA-900-3 : fetchmail - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Due to restrictive dependency definition for fetchmail-ssl the updated
fetchmailconf package couldn't be installed on the old stable
distribution (woody) together with fetchmail-ssl.  Hence, this update
loosens it, so that the update can be pulled in.  For completeness
we're including the original advisory text :

  Thomas Wolff discovered that the fetchmailconf program which is
  provided as part of fetchmail, an SSL enabled POP3, APOP, IMAP mail
  gatherer/forwarder, creates the new configuration in an insecure
  fashion that can lead to leaking passwords for mail accounts to
  local users.

This update also fixes a regression in the package for stable caused
by the last security update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=336096"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-900"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the fetchmail package.

For the old stable distribution (woody) this problem has been fixed in
version 5.9.11-6.4 of fetchmail and in version 5.9.11-6.3 of
fetchmail-ssl.

For the stable distribution (sarge) this problem has been fixed in
version 6.2.5-12sarge3."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fetchmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"fetchmail", reference:"5.9.11-6.4")) flag++;
if (deb_check(release:"3.0", prefix:"fetchmail-common", reference:"5.9.11-6.4")) flag++;
if (deb_check(release:"3.0", prefix:"fetchmail-ssl", reference:"5.9.11-6.3")) flag++;
if (deb_check(release:"3.0", prefix:"fetchmailconf", reference:"5.9.11-6.4")) flag++;
if (deb_check(release:"3.1", prefix:"fetchmail", reference:"6.2.5-12sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"fetchmail-ssl", reference:"6.2.5-12sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"fetchmailconf", reference:"6.2.5-12sarge3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
