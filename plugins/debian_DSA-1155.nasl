#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1155. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22697);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/17 23:41:26 $");

  script_cve_id("CVE-2006-1173");
  script_bugtraq_id(18433);
  script_osvdb_id(26197);
  script_xref(name:"CERT", value:"146718");
  script_xref(name:"DSA", value:"1155");

  script_name(english:"Debian DSA-1155-2 : sendmail - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It turned out that the sendmail binary depends on libsasl2 (>=
2.1.19.dfsg1) which is neither available in the stable nor in the
security archive. This version is scheduled for the inclusion in the
next update of the stable release, though.

You'll have to download the referenced file for your architecture from
below and install it with dpkg -i.

As an alternative, temporarily adding the following line to
/etc/apt/sources.list will mitigate the problem as well :

  deb http://ftp.debian.de/debian stable-proposed-updates main

Here is the original security advisory for completeness :

  Frank Sheiness discovered that a MIME conversion routine in
  sendmail, a powerful, efficient, and scalable mail transport agent,
  could be tricked by a specially crafted mail to perform an endless
  recursion."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=373801"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=380258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1155"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the sendmail package.

For the stable distribution (sarge) this problem has been fixed in
version 8.13.4-3sarge2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sendmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libmilter-dev", reference:"8.13.4-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libmilter0", reference:"8.13.4-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libsasl2", reference:"2.1.19.dfsg1-0sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"rmail", reference:"8.13.4-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"sendmail", reference:"8.13.4-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"sendmail-base", reference:"8.13.4-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"sendmail-bin", reference:"8.13.4-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"sendmail-cf", reference:"8.13.4-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"sendmail-doc", reference:"8.13.4-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"sensible-mda", reference:"8.13.4-3sarge2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
