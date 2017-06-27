#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2813. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71276);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/19 17:45:44 $");

  script_cve_id("CVE-2013-1913", "CVE-2013-1978");
  script_bugtraq_id(64098, 64105);
  script_osvdb_id(84830, 84831, 87792, 100614, 100615);
  script_xref(name:"DSA", value:"2813");

  script_name(english:"Debian DSA-2813-1 : gimp - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Murray McAllister discovered multiple integer and buffer overflows in
the XWD plugin in Gimp, which can result in the execution of arbitrary
code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3403"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3481"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-5576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/gimp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/gimp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2813"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gimp packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 2.6.10-1+squeeze4. This update also fixes
CVE-2012-3403, CVE-2012-3481 and CVE-2012-5576.

For the stable distribution (wheezy), these problems have been fixed
in version 2.8.2-2+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gimp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"gimp", reference:"2.6.10-1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"gimp-data", reference:"2.6.10-1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"gimp-dbg", reference:"2.6.10-1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libgimp2.0", reference:"2.6.10-1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libgimp2.0-dev", reference:"2.6.10-1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libgimp2.0-doc", reference:"2.6.10-1+squeeze4")) flag++;
if (deb_check(release:"7.0", prefix:"gimp", reference:"2.8.2-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"gimp-data", reference:"2.8.2-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"gimp-dbg", reference:"2.8.2-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgimp2.0", reference:"2.8.2-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgimp2.0-dev", reference:"2.8.2-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgimp2.0-doc", reference:"2.8.2-2+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
