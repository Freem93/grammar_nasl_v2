#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1933. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44798);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/03/19 14:28:19 $");

  script_cve_id("CVE-2009-2820");
  script_bugtraq_id(36958);
  script_osvdb_id(59854);
  script_xref(name:"DSA", value:"1933");

  script_name(english:"Debian DSA-1933-1 : cups - missing input sanitising");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Aaron Siegel discovered that the web interface of cups, the Common
UNIX Printing System, is prone to cross-site scripting attacks."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1933"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the cups packages.

For the oldstable distribution (etch), this problem has been fixed in
version 1.2.7-4+etch9.

For the stable distribution (lenny), this problem has been fixed in
version 1.3.8-1+lenny7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"cupsys", reference:"1.2.7-4+etch9")) flag++;
if (deb_check(release:"4.0", prefix:"cupsys-bsd", reference:"1.2.7-4+etch9")) flag++;
if (deb_check(release:"4.0", prefix:"cupsys-client", reference:"1.2.7-4+etch9")) flag++;
if (deb_check(release:"4.0", prefix:"cupsys-common", reference:"1.2.7-4+etch9")) flag++;
if (deb_check(release:"4.0", prefix:"cupsys-dbg", reference:"1.2.7-4+etch9")) flag++;
if (deb_check(release:"4.0", prefix:"libcupsimage2", reference:"1.2.7-4+etch9")) flag++;
if (deb_check(release:"4.0", prefix:"libcupsimage2-dev", reference:"1.2.7-4+etch9")) flag++;
if (deb_check(release:"4.0", prefix:"libcupsys2", reference:"1.2.7-4+etch9")) flag++;
if (deb_check(release:"4.0", prefix:"libcupsys2-dev", reference:"1.2.7-4+etch9")) flag++;
if (deb_check(release:"4.0", prefix:"libcupsys2-gnutls10", reference:"1.2.7-4+etch9")) flag++;
if (deb_check(release:"5.0", prefix:"cups", reference:"1.3.8-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"cups-bsd", reference:"1.3.8-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"cups-client", reference:"1.3.8-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"cups-common", reference:"1.3.8-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"cups-dbg", reference:"1.3.8-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"cupsys", reference:"1.3.8-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"cupsys-bsd", reference:"1.3.8-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"cupsys-client", reference:"1.3.8-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"cupsys-common", reference:"1.3.8-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"cupsys-dbg", reference:"1.3.8-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"libcups2", reference:"1.3.8-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"libcups2-dev", reference:"1.3.8-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"libcupsimage2", reference:"1.3.8-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"libcupsimage2-dev", reference:"1.3.8-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"libcupsys2", reference:"1.3.8-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"libcupsys2-dev", reference:"1.3.8-1+lenny7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
