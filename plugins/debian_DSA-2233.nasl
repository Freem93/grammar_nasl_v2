#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2233. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53860);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2009-2939", "CVE-2011-0411", "CVE-2011-1720");
  script_bugtraq_id(36469, 46767, 47778);
  script_osvdb_id(71946, 72259);
  script_xref(name:"DSA", value:"2233");

  script_name(english:"Debian DSA-2233-1 : postfix - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Postfix, a mail transfer
agent. The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2009-2939
    The postinst script grants the postfix user write access
    to /var/spool/postfix/pid, which might allow local users
    to conduct symlink attacks that overwrite arbitrary
    files.

  - CVE-2011-0411
    The STARTTLS implementation does not properly restrict
    I/O buffering, which allows man-in-the-middle attackers
    to insert commands into encrypted SMTP sessions by
    sending a cleartext command that is processed after TLS
    is in place.

  - CVE-2011-1720
    A heap-based read-only buffer overflow allows malicious
    clients to crash the smtpd server process using a
    crafted SASL authentication request."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2939"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1720"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/postfix"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2233"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the postfix packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 2.5.5-1.1+lenny1.

For the stable distribution (squeeze), this problem has been fixed in
version 2.7.1-1+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postfix");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/11");
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
if (deb_check(release:"5.0", prefix:"postfix", reference:"2.5.5-1.1+lenny1")) flag++;
if (deb_check(release:"6.0", prefix:"postfix", reference:"2.7.1-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postfix-cdb", reference:"2.7.1-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postfix-dev", reference:"2.7.1-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postfix-doc", reference:"2.7.1-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postfix-ldap", reference:"2.7.1-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postfix-mysql", reference:"2.7.1-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postfix-pcre", reference:"2.7.1-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postfix-pgsql", reference:"2.7.1-1+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
