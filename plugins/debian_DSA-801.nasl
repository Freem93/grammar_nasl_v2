#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-801. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19571);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/05/18 00:15:59 $");

  script_cve_id("CVE-2005-2496");
  script_osvdb_id(19055);
  script_xref(name:"DSA", value:"801");

  script_name(english:"Debian DSA-801-1 : ntp - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SuSE developers discovered that ntp confuses the given group id with
the group id of the given user when called with a group id on the
commandline that is specified as a string and not as a numeric gid,
which causes ntpd to run with different privileges than intended."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-801"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ntp-server package.

The old stable distribution (woody) is not affected by this problem.

For the stable distribution (sarge) this problem has been fixed in
version 4.2.0a+stable-2sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"ntp", reference:"4.2.0a+stable-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"ntp-doc", reference:"4.2.0a+stable-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"ntp-refclock", reference:"4.2.0a+stable-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"ntp-server", reference:"4.2.0a+stable-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"ntp-simple", reference:"4.2.0a+stable-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"ntpdate", reference:"4.2.0a+stable-2sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
