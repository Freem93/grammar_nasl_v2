#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3740. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95936);
  script_version("$Revision: 3.6 $");
  script_cvs_date("$Date: 2017/03/31 21:35:24 $");

  script_cve_id("CVE-2016-2119", "CVE-2016-2123", "CVE-2016-2125", "CVE-2016-2126");
  script_osvdb_id(141072, 149000, 149001, 149002);
  script_xref(name:"DSA", value:"3740");

  script_name(english:"Debian DSA-3740-1 : samba - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Samba, a SMB/CIFS
file, print, and login server for Unix. The Common Vulnerabilities and
Exposures project identifies the following issues :

  - CVE-2016-2119
    Stefan Metzmacher discovered that client-side SMB2/3
    required signing can be downgraded, allowing a
    man-in-the-middle attacker to impersonate a server being
    connected to by Samba, and return malicious results.

  - CVE-2016-2123
    Trend Micro's Zero Day Initiative and Frederic Besler
    discovered that the routine ndr_pull_dnsp_name, used to
    parse data from the Samba Active Directory ldb database,
    contains an integer overflow flaw, leading to an
    attacker-controlled memory overwrite. An authenticated
    user can take advantage of this flaw for remote
    privilege escalation.

  - CVE-2016-2125
    Simo Sorce of Red Hat discovered that the Samba client
    code always requests a forwardable ticket when using
    Kerberos authentication. A target server, which must be
    in the current or trusted domain/realm, is given a valid
    general purpose Kerberos 'Ticket Granting Ticket' (TGT),
    which can be used to fully impersonate the authenticated
    user or service.

  - CVE-2016-2126
    Volker Lendecke discovered several flaws in the Kerberos
    PAC validation. A remote, authenticated, attacker can
    cause the winbindd process to crash using a legitimate
    Kerberos ticket due to incorrect handling of the PAC
    checksum. A local service with access to the winbindd
    privileged pipe can cause winbindd to cache elevated
    access permissions."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=830195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/samba"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3740"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the samba packages.

For the stable distribution (jessie), these problems have been fixed
in version 2:4.2.14+dfsg-0+deb8u2. In addition, this update contains
several changes originally targeted for the upcoming jessie point
release."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"libnss-winbind", reference:"2:4.2.14+dfsg-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpam-smbpass", reference:"2:4.2.14+dfsg-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpam-winbind", reference:"2:4.2.14+dfsg-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libparse-pidl-perl", reference:"2:4.2.14+dfsg-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libsmbclient", reference:"2:4.2.14+dfsg-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libsmbclient-dev", reference:"2:4.2.14+dfsg-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libsmbsharemodes-dev", reference:"2:4.2.14+dfsg-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libsmbsharemodes0", reference:"2:4.2.14+dfsg-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libwbclient-dev", reference:"2:4.2.14+dfsg-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libwbclient0", reference:"2:4.2.14+dfsg-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python-samba", reference:"2:4.2.14+dfsg-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"registry-tools", reference:"2:4.2.14+dfsg-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"samba", reference:"2:4.2.14+dfsg-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"samba-common", reference:"2:4.2.14+dfsg-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"samba-common-bin", reference:"2:4.2.14+dfsg-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"samba-dbg", reference:"2:4.2.14+dfsg-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"samba-dev", reference:"2:4.2.14+dfsg-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"samba-doc", reference:"2:4.2.14+dfsg-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"samba-dsdb-modules", reference:"2:4.2.14+dfsg-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"samba-libs", reference:"2:4.2.14+dfsg-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"samba-testsuite", reference:"2:4.2.14+dfsg-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"samba-vfs-modules", reference:"2:4.2.14+dfsg-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"smbclient", reference:"2:4.2.14+dfsg-0+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"winbind", reference:"2:4.2.14+dfsg-0+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
