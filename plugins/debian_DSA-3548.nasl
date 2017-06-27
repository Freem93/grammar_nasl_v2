#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3548. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(90515);
  script_version("$Revision: 2.13 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2015-5370", "CVE-2016-2110", "CVE-2016-2111", "CVE-2016-2112", "CVE-2016-2113", "CVE-2016-2114", "CVE-2016-2115", "CVE-2016-2118");
  script_osvdb_id(136339, 136989, 136990, 136991, 136992, 136993, 136994, 136995);
  script_xref(name:"DSA", value:"3548");

  script_name(english:"Debian DSA-3548-1 : samba - security update (Badlock)");
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

  - CVE-2015-5370
    Jouni Knuutinen from Synopsys discovered flaws in the
    Samba DCE-RPC code which can lead to denial of service
    (crashes and high cpu consumption) and man-in-the-middle
    attacks.

  - CVE-2016-2110
    Stefan Metzmacher of SerNet and the Samba Team
    discovered that the feature negotiation of NTLMSSP does
    not protect against downgrade attacks.

  - CVE-2016-2111
    When Samba is configured as domain controller, it allows
    remote attackers to spoof the computer name of a secure
    channel's endpoint, and obtain sensitive session
    information. This flaw corresponds to the same
    vulnerability as CVE-2015-0005 for Windows, discovered
    by Alberto Solino from Core Security.

  - CVE-2016-2112
    Stefan Metzmacher of SerNet and the Samba Team
    discovered that a man-in-the-middle attacker can
    downgrade LDAP connections to avoid integrity
    protection.

  - CVE-2016-2113
    Stefan Metzmacher of SerNet and the Samba Team
    discovered that man-in-the-middle attacks are possible
    for client triggered LDAP connections and ncacn_http
    connections.

  - CVE-2016-2114
    Stefan Metzmacher of SerNet and the Samba Team
    discovered that Samba does not enforce required smb
    signing even if explicitly configured.

  - CVE-2016-2115
    Stefan Metzmacher of SerNet and the Samba Team
    discovered that SMB connections for IPC traffic are not
    integrity-protected.

  - CVE-2016-2118
    Stefan Metzmacher of SerNet and the Samba Team
    discovered that a man-in-the-middle attacker can
    intercept any DCERPC traffic between a client and a
    server in order to impersonate the client and obtain the
    same privileges as the authenticated user account."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-0005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2113"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2113"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/latest_news.html#4.4.2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/history/samba-4.2.0.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/history/samba-4.2.10.html"
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
    value:"http://www.debian.org/security/2016/dsa-3548"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the samba packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 2:3.6.6-6+deb7u9. The oldstable distribution is not
affected by CVE-2016-2113 and CVE-2016-2114.

For the stable distribution (jessie), these problems have been fixed
in version 2:4.2.10+dfsg-0+deb8u1. The issues were addressed by
upgrading to the new upstream version 4.2.10, which includes
additional changes and bugfixes. The depending libraries ldb, talloc,
tdb and tevent required as well an update to new upstream versions for
this update.

Please refer to

  - https://www.samba.org/samba/latest_news.html#4.4.2
  - https://www.samba.org/samba/history/samba-4.2.0.html

  - https://www.samba.org/samba/history/samba-4.2.10.html

for further details (in particular for new options and defaults).


We'd like to thank Andreas Schneider and Guenther Deschner (Red Hat),
Stefan Metzmacher and Ralph Boehme (SerNet) and Aurelien Aptel (SUSE)
for the massive backporting work required to support Samba 3.6 and
Samba 4.2 and Andrew Bartlett (Catalyst), Jelmer Vernooij and Mathieu
Parent for their help in preparing updates of Samba and the underlying
infrastructure libraries."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/13");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/14");
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
if (deb_check(release:"7.0", prefix:"libnss-winbind", reference:"2:3.6.6-6+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"libpam-smbpass", reference:"2:3.6.6-6+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"libpam-winbind", reference:"2:3.6.6-6+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"libsmbclient", reference:"2:3.6.6-6+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"libsmbclient-dev", reference:"2:3.6.6-6+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"libwbclient-dev", reference:"2:3.6.6-6+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"libwbclient0", reference:"2:3.6.6-6+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"samba", reference:"2:3.6.6-6+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"samba-common", reference:"2:3.6.6-6+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"samba-common-bin", reference:"2:3.6.6-6+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"samba-dbg", reference:"2:3.6.6-6+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"samba-doc", reference:"2:3.6.6-6+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"samba-doc-pdf", reference:"2:3.6.6-6+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"samba-tools", reference:"2:3.6.6-6+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"smbclient", reference:"2:3.6.6-6+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"swat", reference:"2:3.6.6-6+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"winbind", reference:"2:3.6.6-6+deb7u9")) flag++;
if (deb_check(release:"8.0", prefix:"libnss-winbind", reference:"2:4.2.10+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpam-smbpass", reference:"2:4.2.10+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpam-winbind", reference:"2:4.2.10+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libparse-pidl-perl", reference:"2:4.2.10+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsmbclient", reference:"2:4.2.10+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsmbclient-dev", reference:"2:4.2.10+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsmbsharemodes-dev", reference:"2:4.2.10+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsmbsharemodes0", reference:"2:4.2.10+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwbclient-dev", reference:"2:4.2.10+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwbclient0", reference:"2:4.2.10+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"python-samba", reference:"2:4.2.10+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"registry-tools", reference:"2:4.2.10+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"samba", reference:"2:4.2.10+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"samba-common", reference:"2:4.2.10+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"samba-common-bin", reference:"2:4.2.10+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"samba-dbg", reference:"2:4.2.10+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"samba-dev", reference:"2:4.2.10+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"samba-doc", reference:"2:4.2.10+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"samba-dsdb-modules", reference:"2:4.2.10+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"samba-libs", reference:"2:4.2.10+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"samba-testsuite", reference:"2:4.2.10+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"samba-vfs-modules", reference:"2:4.2.10+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"smbclient", reference:"2:4.2.10+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"winbind", reference:"2:4.2.10+dfsg-0+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
