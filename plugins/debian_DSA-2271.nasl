#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2271. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55491);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:31:55 $");

  script_cve_id("CVE-2011-2192");
  script_xref(name:"DSA", value:"2271");

  script_name(english:"Debian DSA-2271-1 : curl - improper delegation of client credentials");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Richard Silverman discovered that when doing GSSAPI authentication,
libcurl unconditionally performs credential delegation. This hands the
server a copy of the client's security credentials, allowing the
server to impersonate the client to any other using the same GSSAPI
mechanism. This is obviously a very sensitive operation, which should
only be done when the user explicitly so directs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/curl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2271"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the curl packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 7.18.2-8lenny5.

For the stable distribution (squeeze), this problem has been fixed in
version 7.21.0-2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/05");
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
if (deb_check(release:"5.0", prefix:"curl", reference:"7.18.2-8lenny5")) flag++;
if (deb_check(release:"6.0", prefix:"curl", reference:"7.21.0-2")) flag++;
if (deb_check(release:"6.0", prefix:"libcurl3", reference:"7.21.0-2")) flag++;
if (deb_check(release:"6.0", prefix:"libcurl3-dbg", reference:"7.21.0-2")) flag++;
if (deb_check(release:"6.0", prefix:"libcurl3-gnutls", reference:"7.21.0-2")) flag++;
if (deb_check(release:"6.0", prefix:"libcurl4-gnutls-dev", reference:"7.21.0-2")) flag++;
if (deb_check(release:"6.0", prefix:"libcurl4-openssl-dev", reference:"7.21.0-2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
