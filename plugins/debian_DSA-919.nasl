#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-919. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22785);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2013/05/18 00:19:43 $");

  script_cve_id("CVE-2005-3185", "CVE-2005-4077");
  script_bugtraq_id(15102, 15756);
  script_osvdb_id(20012, 21509);
  script_xref(name:"DSA", value:"919");

  script_name(english:"Debian DSA-919-2 : curl - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The upstream developer of curl, a multi-protocol file transfer
library, informed us that the former correction to several off-by-one
errors are not sufficient. For completeness please find the original
bug description below :

  Several problems were discovered in libcurl, a multi-protocol file
  transfer library. The Common Vulnerabilities and Exposures project
  identifies the following problems :

    - CVE-2005-3185
      A buffer overflow has been discovered in libcurl that
      could allow the execution of arbitrary code.

    - CVE-2005-4077
      Stefan Esser discovered several off-by-one errors that
      allows local users to trigger a buffer overflow and
      cause a denial of service or bypass PHP security
      restrictions via certain URLs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=342339"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=342696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-919"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libcurl packages.

For the old stable distribution (woody) these problems have been fixed
in version 7.9.5-1woody2.

For the stable distribution (sarge) these problems have been fixed in
version 7.13.2-2sarge5. This update also includes a bugfix against
data corruption."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"curl", reference:"7.9.5-1woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libcurl-dev", reference:"7.9.5-1woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libcurl2", reference:"7.9.5-1woody2")) flag++;
if (deb_check(release:"3.1", prefix:"curl", reference:"7.13.2-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libcurl3", reference:"7.13.2-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libcurl3-dbg", reference:"7.13.2-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libcurl3-dev", reference:"7.13.2-2sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libcurl3-gssapi", reference:"7.13.2-2sarge5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
