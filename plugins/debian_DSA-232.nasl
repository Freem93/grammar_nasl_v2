#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-232. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15069);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2013/05/18 00:02:52 $");

  script_cve_id("CVE-2002-1366", "CVE-2002-1367", "CVE-2002-1368", "CVE-2002-1369", "CVE-2002-1371", "CVE-2002-1372", "CVE-2002-1383", "CVE-2002-1384");
  script_bugtraq_id(6435, 6436, 6437, 6438, 6439, 6440, 6475);
  script_osvdb_id(10743);
  script_xref(name:"DSA", value:"232");

  script_name(english:"Debian DSA-232-1 : cupsys - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in the Common Unix Printing
System (CUPS). Several of these issues represent the potential for a
remote compromise or denial of service. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CAN-2002-1383: Multiple integer overflows allow a remote
    attacker to execute arbitrary code via the CUPSd HTTP
    interface and the image handling code in CUPS filters.
  - CAN-2002-1366: Race conditions in connection with
    /etc/cups/certs/ allow local users with lp privileges to
    create or overwrite arbitrary files. This is not present
    in the potato version.

  - CAN-2002-1367: This vulnerability allows a remote
    attacker to add printers without authentication via a
    certain UDP packet, which can then be used to perform
    unauthorized activities such as stealing the local root
    certificate for the administration server via a 'need
    authorization' page.

  - CAN-2002-1368: Negative lengths fed into memcpy() can
    cause a denial of service and possibly execute arbitrary
    code.

  - CAN-2002-1369: An unsafe strncat() function call
    processing the options string allows a remote attacker
    to execute arbitrary code via a buffer overflow.

  - CAN-2002-1371: Zero width images allows a remote
    attacker to execute arbitrary code via modified chunk
    headers.

  - CAN-2002-1372: CUPS does not properly check the return
    values of various file and socket operations, which
    could allow a remote attacker to cause a denial of
    service.

  - CAN-2002-1384: The cupsys package contains some code
    from the xpdf package, used to convert PDF files for
    printing, which contains an exploitable integer overflow
    bug. This is not present in the potato version.

Even though we tried very hard to fix all problems in the packages for
potato as well, the packages may still contain other security related
problems. Hence, we advise users of potato systems using CUPS to
upgrade to woody soon."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.idefense.com/advisory/12.19.02.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-232"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the CUPS packages immediately.

For the current stable distribution (woody), these problems have been
fixed in version 1.1.14-4.3.

For the old stable distribution (potato), these problems have been
fixed in version 1.0.4-12.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cupsys");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/12/19");
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
if (deb_check(release:"2.2", prefix:"cupsys", reference:"1.0.4-12.1")) flag++;
if (deb_check(release:"2.2", prefix:"cupsys-bsd", reference:"1.0.4-12.1")) flag++;
if (deb_check(release:"2.2", prefix:"libcupsys1", reference:"1.0.4-12.1")) flag++;
if (deb_check(release:"2.2", prefix:"libcupsys1-dev", reference:"1.0.4-12.1")) flag++;
if (deb_check(release:"3.0", prefix:"cupsys", reference:"1.1.14-4.4")) flag++;
if (deb_check(release:"3.0", prefix:"cupsys-bsd", reference:"1.1.14-4.4")) flag++;
if (deb_check(release:"3.0", prefix:"cupsys-client", reference:"1.1.14-4.4")) flag++;
if (deb_check(release:"3.0", prefix:"cupsys-pstoraster", reference:"1.1.14-4.4")) flag++;
if (deb_check(release:"3.0", prefix:"libcupsys2", reference:"1.1.14-4.4")) flag++;
if (deb_check(release:"3.0", prefix:"libcupsys2-dev", reference:"1.1.14-4.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
