#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2829. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71769);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/16 15:43:10 $");

  script_cve_id("CVE-2013-0200", "CVE-2013-4325", "CVE-2013-6402", "CVE-2013-6427");
  script_bugtraq_id(58079, 62499, 63959, 64131);
  script_osvdb_id(90543, 97509, 100377, 100651);
  script_xref(name:"DSA", value:"2829");

  script_name(english:"Debian DSA-2829-1 : hplip - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been found in the HP Linux Printing and
Imaging System: Insecure temporary files, insufficient permission
checks in PackageKit and the insecure hp-upgrade service has been
disabled."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/hplip"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/hplip"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2829"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the hplip packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 3.10.6-2+squeeze2.

For the stable distribution (wheezy), these problems have been fixed
in version 3.12.6-3.1+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hplip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"hpijs", reference:"3.10.6-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"hpijs-ppds", reference:"3.10.6-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"hplip", reference:"3.10.6-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"hplip-cups", reference:"3.10.6-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"hplip-data", reference:"3.10.6-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"hplip-dbg", reference:"3.10.6-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"hplip-doc", reference:"3.10.6-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"hplip-gui", reference:"3.10.6-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libhpmud-dev", reference:"3.10.6-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libhpmud0", reference:"3.10.6-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libsane-hpaio", reference:"3.10.6-2+squeeze2")) flag++;
if (deb_check(release:"7.0", prefix:"hpijs", reference:"3.12.6-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hpijs-ppds", reference:"3.12.6-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hplip", reference:"3.12.6-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hplip-cups", reference:"3.12.6-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hplip-data", reference:"3.12.6-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hplip-dbg", reference:"3.12.6-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hplip-doc", reference:"3.12.6-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"hplip-gui", reference:"3.12.6-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libhpmud-dev", reference:"3.12.6-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libhpmud0", reference:"3.12.6-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libsane-hpaio", reference:"3.12.6-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"printer-driver-hpcups", reference:"3.12.6-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"printer-driver-hpijs", reference:"3.12.6-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"printer-driver-postscript-hp", reference:"3.12.6-3.1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
