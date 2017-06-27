#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-135. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14972);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/17 23:41:28 $");

  script_cve_id("CVE-2002-0653");
  script_bugtraq_id(5084);
  script_xref(name:"DSA", value:"135");

  script_name(english:"Debian DSA-135-1 : libapache-mod-ssl - buffer overflow / DoS");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The libapache-mod-ssl package provides SSL capability to the apache
webserver. Recently, a problem has been found in the handling of
.htaccess files, allowing arbitrary code execution as the web server
user (regardless of ExecCGI / suexec settings), DoS attacks (killing
off apache children), and allowing someone to take control of apache
child processes - all through specially crafted .htaccess files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-135"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"This has been fixed in the libapache-mod-ssl_2.4.10-1.3.9-1potato2
package (for potato), and the libapache-mod-ssl_2.8.9-2 package (for
woody). We recommend you upgrade as soon as possible."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache-mod-ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
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
if (deb_check(release:"2.2", prefix:"libapache-mod-ssl", reference:"2.4.10-1.3.9-1potato2")) flag++;
if (deb_check(release:"2.2", prefix:"libapache-mod-ssl-doc", reference:"2.4.10-1.3.9-1potato2")) flag++;
if (deb_check(release:"3.0", prefix:"libapache-mod-ssl", reference:"2.8.9-2")) flag++;
if (deb_check(release:"3.0", prefix:"libapache-mod-ssl-doc", reference:"2.8.9-2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
