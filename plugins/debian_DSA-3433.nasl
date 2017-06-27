#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3433. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87684);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2015-3223", "CVE-2015-5252", "CVE-2015-5296", "CVE-2015-5299", "CVE-2015-5330", "CVE-2015-7540", "CVE-2015-8467");
  script_osvdb_id(131934, 131935, 131936, 131937, 131938, 131939, 131940);
  script_xref(name:"DSA", value:"3433");

  script_name(english:"Debian DSA-3433-1 : samba - security update");
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

  - CVE-2015-3223
    Thilo Uttendorfer of Linux Information Systems AG
    discovered that a malicious request can cause the Samba
    LDAP server to hang, spinning using CPU. A remote
    attacker can take advantage of this flaw to mount a
    denial of service.

  - CVE-2015-5252
    Jan 'Yenya' Kasprzak and the Computer Systems Unit team
    at Faculty of Informatics, Masaryk University discovered
    that insufficient symlink verification could allow data
    access outside an exported share path.

  - CVE-2015-5296
    Stefan Metzmacher of SerNet discovered that Samba does
    not ensure that signing is negotiated when creating an
    encrypted client connection to a server. This allows a
    man-in-the-middle attacker to downgrade the connection
    and connect using the supplied credentials as an
    unsigned, unencrypted connection.

  - CVE-2015-5299
    It was discovered that a missing access control check in
    the VFS shadow_copy2 module could allow unauthorized
    users to access snapshots.

  - CVE-2015-5330
    Douglas Bagnall of Catalyst discovered that the Samba
    LDAP server is vulnerable to a remote memory read
    attack. A remote attacker can obtain sensitive
    information from daemon heap memory by sending crafted
    packets and then either read an error message, or a
    database value.

  - CVE-2015-7540
    It was discovered that a malicious client can send
    packets that cause the LDAP server provided by the AD DC
    in the samba daemon process to consume unlimited memory
    and be terminated.

  - CVE-2015-8467
    Andrew Bartlett of the Samba Team and Catalyst
    discovered that a Samba server deployed as an AD DC can
    expose Windows DCs in the same domain to a denial of
    service via the creation of multiple machine accounts.
    This issue is related to the MS15-096 / CVE-2015-2535
    security issue in Windows."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8467"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-2535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/samba"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/samba"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3433"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the samba packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 2:3.6.6-6+deb7u6. The oldstable distribution (wheezy)
is only affected by CVE-2015-5252, CVE-2015-5296 and CVE-2015-5299.

For the stable distribution (jessie), these problems have been fixed
in version 2:4.1.17+dfsg-2+deb8u1. The fixes for CVE-2015-3223 and
CVE-2015-5330 required an update to ldb 2:1.1.17-2+deb8u1 to correct
the defects."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libnss-winbind", reference:"2:3.6.6-6+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libpam-smbpass", reference:"2:3.6.6-6+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libpam-winbind", reference:"2:3.6.6-6+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libsmbclient", reference:"2:3.6.6-6+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libsmbclient-dev", reference:"2:3.6.6-6+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libwbclient-dev", reference:"2:3.6.6-6+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libwbclient0", reference:"2:3.6.6-6+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"samba", reference:"2:3.6.6-6+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"samba-common", reference:"2:3.6.6-6+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"samba-common-bin", reference:"2:3.6.6-6+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"samba-dbg", reference:"2:3.6.6-6+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"samba-doc", reference:"2:3.6.6-6+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"samba-doc-pdf", reference:"2:3.6.6-6+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"samba-tools", reference:"2:3.6.6-6+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"smbclient", reference:"2:3.6.6-6+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"swat", reference:"2:3.6.6-6+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"winbind", reference:"2:3.6.6-6+deb7u6")) flag++;
if (deb_check(release:"8.0", prefix:"libnss-winbind", reference:"2:4.1.17+dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpam-smbpass", reference:"2:4.1.17+dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpam-winbind", reference:"2:4.1.17+dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libparse-pidl-perl", reference:"2:4.1.17+dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsmbclient", reference:"2:4.1.17+dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsmbclient-dev", reference:"2:4.1.17+dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsmbsharemodes-dev", reference:"2:4.1.17+dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsmbsharemodes0", reference:"2:4.1.17+dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwbclient-dev", reference:"2:4.1.17+dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwbclient0", reference:"2:4.1.17+dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"python-samba", reference:"2:4.1.17+dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"registry-tools", reference:"2:4.1.17+dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"samba", reference:"2:4.1.17+dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"samba-common", reference:"2:4.1.17+dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"samba-common-bin", reference:"2:4.1.17+dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"samba-dbg", reference:"2:4.1.17+dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"samba-dev", reference:"2:4.1.17+dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"samba-doc", reference:"2:4.1.17+dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"samba-dsdb-modules", reference:"2:4.1.17+dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"samba-libs", reference:"2:4.1.17+dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"samba-testsuite", reference:"2:4.1.17+dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"samba-vfs-modules", reference:"2:4.1.17+dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"smbclient", reference:"2:4.1.17+dfsg-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"winbind", reference:"2:4.1.17+dfsg-2+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
