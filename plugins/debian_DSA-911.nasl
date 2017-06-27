#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-911. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22777);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/01/04 15:13:58 $");

  script_cve_id("CVE-2005-2975", "CVE-2005-2976", "CVE-2005-3186");
  script_bugtraq_id(15428);
  script_osvdb_id(20840, 20841, 20842);
  script_xref(name:"DSA", value:"911");

  script_name(english:"Debian DSA-911-1 : gtk+2.0 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been found in gtk+2.0, the Gtk+ GdkPixBuf
XPM image rendering library. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2005-2975
    Ludwig Nussel discovered an infinite loop when
    processing XPM images that allows an attacker to cause a
    denial of service via a specially crafted XPM file.

  - CVE-2005-2976
    Ludwig Nussel discovered an integer overflow in the way
    XPM images are processed that could lead to the
    execution of arbitrary code or crash the application via
    a specially crafted XPM file.

  - CVE-2005-3186
    'infamous41md' discovered an integer overflow in the XPM
    processing routine that can be used to execute arbitrary
    code via a traditional heap overflow."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=339431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-911"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gtk+2.0 packages.

The following matrix explains which versions fix these problems :

                     old stable (woody)  stable (sarge)      unstable (sid)      
  gdk-pixbuf          0.17.0-2woody3      0.22.0-8.1          0.22.0-11           
  gtk+2.0             2.0.2-5woody3       2.6.4-3.1           2.6.10-2"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gtk+2.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"gtk2.0-examples", reference:"2.0.2-5woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libgtk-common", reference:"2.0.2-5woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libgtk2.0-0", reference:"2.0.2-5woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libgtk2.0-common", reference:"2.0.2-5woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libgtk2.0-dbg", reference:"2.0.2-5woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libgtk2.0-dev", reference:"2.0.2-5woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libgtk2.0-doc", reference:"2.0.2-5woody3")) flag++;
if (deb_check(release:"3.1", prefix:"gtk2-engines-pixbuf", reference:"2.6.4-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"gtk2.0-examples", reference:"2.6.4-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"libgtk2.0-0", reference:"2.6.4-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"libgtk2.0-0-dbg", reference:"2.6.4-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"libgtk2.0-bin", reference:"2.6.4-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"libgtk2.0-common", reference:"2.6.4-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"libgtk2.0-dev", reference:"2.6.4-3.1")) flag++;
if (deb_check(release:"3.1", prefix:"libgtk2.0-doc", reference:"2.6.4-3.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
