#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-181. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15018);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2014/08/14 14:19:28 $");

  script_cve_id("CVE-2002-1157");
  script_bugtraq_id(6029);
  script_xref(name:"DSA", value:"181");

  script_name(english:"Debian DSA-181-1 : libapache-mod-ssl - XSS");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Joe Orton discovered a cross site scripting problem in mod_ssl, an
Apache module that adds Strong cryptography (i.e. HTTPS support) to
the webserver. The module will return the server name unescaped in the
response to an HTTP request on an SSL port.

Like the other recent Apache XSS bugs, this only affects servers using
a combination of 'UseCanonicalName off' (default in the Debian package
of Apache) and wildcard DNS. This is very unlikely to happen, though.
Apache 2.0/mod_ssl is not vulnerable since it already escapes this
HTML.

With this setting turned on, whenever Apache needs to construct a
self-referencing URL (a URL that refers back to the server the
response is coming from) it will use ServerName and Port to form a
'canonical' name. With this setting off, Apache will use the
hostname:port that the client supplied, when possible. This also
affects SERVER_NAME and SERVER_PORT in CGI scripts."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-181"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libapache-mod-ssl package.

This problem has been fixed in version 2.8.9-2.1 for the current
stable distribution (woody), in version 2.4.10-1.3.9-1potato4 for the
old stable distribution (potato) and version 2.8.9-2.3 for the
unstable distribution (sid)."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache-mod-ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"libapache-mod-ssl", reference:"2.4.10-1.3.9-1potato4")) flag++;
if (deb_check(release:"2.2", prefix:"libapache-mod-ssl-doc", reference:"2.4.10-1.3.9-1potato4")) flag++;
if (deb_check(release:"3.0", prefix:"libapache-mod-ssl", reference:"2.8.9-2.1")) flag++;
if (deb_check(release:"3.0", prefix:"libapache-mod-ssl-doc", reference:"2.8.9-2.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
