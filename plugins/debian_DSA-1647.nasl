#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1647. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34355);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-3658", "CVE-2008-3659", "CVE-2008-3660");
  script_bugtraq_id(30649);
  script_osvdb_id(47796, 47797, 47798);
  script_xref(name:"DSA", value:"1647");

  script_name(english:"Debian DSA-1647-1 : php5 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in PHP, a server-side,
HTML-embedded scripting language. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2008-3658
    Buffer overflow in the imageloadfont function allows a
    denial of service or code execution through a crafted
    font file.

  - CVE-2008-3659
    Buffer overflow in the memnstr function allows a denial
    of service or code execution via a crafted delimiter
    parameter to the explode function.

  - CVE-2008-3660
    Denial of service is possible in the FastCGI module by a
    remote attacker by making a request with multiple dots
    before the extension."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=499987"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=499988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=499989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1647"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the php5 package.

For the stable distribution (etch), these problems have been fixed in
version 5.2.0-8+etch13."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libapache-mod-php5", reference:"5.2.0-8+etch13")) flag++;
if (deb_check(release:"4.0", prefix:"libapache2-mod-php5", reference:"5.2.0-8+etch13")) flag++;
if (deb_check(release:"4.0", prefix:"php-pear", reference:"5.2.0-8+etch13")) flag++;
if (deb_check(release:"4.0", prefix:"php5", reference:"5.2.0-8+etch13")) flag++;
if (deb_check(release:"4.0", prefix:"php5-cgi", reference:"5.2.0-8+etch13")) flag++;
if (deb_check(release:"4.0", prefix:"php5-cli", reference:"5.2.0-8+etch13")) flag++;
if (deb_check(release:"4.0", prefix:"php5-common", reference:"5.2.0-8+etch13")) flag++;
if (deb_check(release:"4.0", prefix:"php5-curl", reference:"5.2.0-8+etch13")) flag++;
if (deb_check(release:"4.0", prefix:"php5-dev", reference:"5.2.0-8+etch13")) flag++;
if (deb_check(release:"4.0", prefix:"php5-gd", reference:"5.2.0-8+etch13")) flag++;
if (deb_check(release:"4.0", prefix:"php5-imap", reference:"5.2.0-8+etch13")) flag++;
if (deb_check(release:"4.0", prefix:"php5-interbase", reference:"5.2.0-8+etch13")) flag++;
if (deb_check(release:"4.0", prefix:"php5-ldap", reference:"5.2.0-8+etch13")) flag++;
if (deb_check(release:"4.0", prefix:"php5-mcrypt", reference:"5.2.0-8+etch13")) flag++;
if (deb_check(release:"4.0", prefix:"php5-mhash", reference:"5.2.0-8+etch13")) flag++;
if (deb_check(release:"4.0", prefix:"php5-mysql", reference:"5.2.0-8+etch13")) flag++;
if (deb_check(release:"4.0", prefix:"php5-odbc", reference:"5.2.0-8+etch13")) flag++;
if (deb_check(release:"4.0", prefix:"php5-pgsql", reference:"5.2.0-8+etch13")) flag++;
if (deb_check(release:"4.0", prefix:"php5-pspell", reference:"5.2.0-8+etch13")) flag++;
if (deb_check(release:"4.0", prefix:"php5-recode", reference:"5.2.0-8+etch13")) flag++;
if (deb_check(release:"4.0", prefix:"php5-snmp", reference:"5.2.0-8+etch13")) flag++;
if (deb_check(release:"4.0", prefix:"php5-sqlite", reference:"5.2.0-8+etch13")) flag++;
if (deb_check(release:"4.0", prefix:"php5-sybase", reference:"5.2.0-8+etch13")) flag++;
if (deb_check(release:"4.0", prefix:"php5-tidy", reference:"5.2.0-8+etch13")) flag++;
if (deb_check(release:"4.0", prefix:"php5-xmlrpc", reference:"5.2.0-8+etch13")) flag++;
if (deb_check(release:"4.0", prefix:"php5-xsl", reference:"5.2.0-8+etch13")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
