#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1738. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35908);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/05 14:49:55 $");

  script_cve_id("CVE-2009-0037");
  script_bugtraq_id(33962);
  script_xref(name:"DSA", value:"1738");

  script_name(english:"Debian DSA-1738-1 : curl - arbitrary file access");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"David Kierznowski discovered that libcurl, a multi-protocol file
transfer library, when configured to follow URL redirects
automatically, does not question the new target location. As libcurl
also supports file:// and scp:// URLs - depending on the setup - an
untrusted server could use that to expose local files, overwrite local
files or even execute arbitrary code via a malicious URL redirect.

This update introduces a new option called CURLOPT_REDIR_PROTOCOLS
which by default does not include the scp and file protocol handlers."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=518423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1738"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the curl packages.

For the oldstable distribution (etch) this problem has been fixed in
version 7.15.5-1etch2.

For the stable distribution (lenny) this problem has been fixed in
version 7.18.2-8lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"curl", reference:"7.15.5-1etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libcurl3", reference:"7.15.5-1etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libcurl3-dbg", reference:"7.15.5-1etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libcurl3-dev", reference:"7.15.5-1etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libcurl3-gnutls", reference:"7.15.5-1etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libcurl3-gnutls-dev", reference:"7.15.5-1etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libcurl3-openssl-dev", reference:"7.15.5-1etch2")) flag++;
if (deb_check(release:"5.0", prefix:"curl", reference:"7.18.2-8lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libcurl3", reference:"7.18.2-8lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libcurl3-dbg", reference:"7.18.2-8lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libcurl3-gnutls", reference:"7.18.2-8lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libcurl4-gnutls-dev", reference:"7.18.2-8lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libcurl4-openssl-dev", reference:"7.18.2-8lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
