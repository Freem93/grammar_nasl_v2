#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3172. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81526);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:23:49 $");

  script_cve_id("CVE-2014-9679");
  script_osvdb_id(118237);
  script_xref(name:"DSA", value:"3172");

  script_name(english:"Debian DSA-3172-1 : cups - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Peter De Wachter discovered that CUPS, the Common UNIX Printing
System, did not correctly parse compressed raster files. By submitting
a specially crafted raster file, a remote attacker could use this
vulnerability to trigger a buffer overflow."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=778387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/cups"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3172"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the cups packages.

For the stable distribution (wheezy), this problem has been fixed in
version 1.5.3-5+deb7u5.

For the upcoming stable distribution (jessie) and unstable
distribution (sid), this problem has been fixed in version 1.7.5-11."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"cups", reference:"1.5.3-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"cups-bsd", reference:"1.5.3-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"cups-client", reference:"1.5.3-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"cups-common", reference:"1.5.3-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"cups-dbg", reference:"1.5.3-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"cups-ppdc", reference:"1.5.3-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"cupsddk", reference:"1.5.3-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libcups2", reference:"1.5.3-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libcups2-dev", reference:"1.5.3-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libcupscgi1", reference:"1.5.3-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libcupscgi1-dev", reference:"1.5.3-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libcupsdriver1", reference:"1.5.3-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libcupsdriver1-dev", reference:"1.5.3-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libcupsimage2", reference:"1.5.3-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libcupsimage2-dev", reference:"1.5.3-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libcupsmime1", reference:"1.5.3-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libcupsmime1-dev", reference:"1.5.3-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libcupsppdc1", reference:"1.5.3-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libcupsppdc1-dev", reference:"1.5.3-5+deb7u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
