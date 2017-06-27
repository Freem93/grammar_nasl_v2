#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3302. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84552);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2015/07/14 13:43:56 $");

  script_cve_id("CVE-2015-0848", "CVE-2015-4588", "CVE-2015-4695", "CVE-2015-4696");
  script_bugtraq_id(74923, 75230, 75329, 75331);
  script_osvdb_id(122812, 123385, 123541, 123542);
  script_xref(name:"DSA", value:"3302");

  script_name(english:"Debian DSA-3302-1 : libwmf - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Insufficient input sanitising in libwmf, a library to process Windows
metafile data, may result in denial of service or the execution of
arbitrary code if a malformed WMF file is opened."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libwmf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libwmf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3302"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libwmf packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 0.2.8.4-10.3+deb7u1.

For the stable distribution (jessie), these problems have been fixed
in version 0.2.8.4-10.3+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwmf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libwmf-bin", reference:"0.2.8.4-10.3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libwmf-dev", reference:"0.2.8.4-10.3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libwmf-doc", reference:"0.2.8.4-10.3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libwmf0.2-7", reference:"0.2.8.4-10.3+deb7u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwmf-bin", reference:"0.2.8.4-10.3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwmf-dev", reference:"0.2.8.4-10.3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwmf-doc", reference:"0.2.8.4-10.3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwmf0.2-7", reference:"0.2.8.4-10.3+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
