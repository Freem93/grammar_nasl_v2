#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:1221 and 
# Oracle Linux Security Advisory ELSA-2011-1221 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68337);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:58:00 $");

  script_cve_id("CVE-2010-0547", "CVE-2011-1678", "CVE-2011-2522", "CVE-2011-2694", "CVE-2011-2724", "CVE-2011-3585");
  script_osvdb_id(74871);
  script_xref(name:"RHSA", value:"2011:1221");

  script_name(english:"Oracle Linux 6 : cifs-utils / samba (ELSA-2011-1221)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:1221 :

Updated samba and cifs-utils packages that fix multiple security
issues and one bug are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Samba is a suite of programs used by machines to share files,
printers, and other information. The cifs-utils package contains
utilities for mounting and managing CIFS (Common Internet File System)
shares.

A cross-site scripting (XSS) flaw was found in the password change
page of the Samba Web Administration Tool (SWAT). If a remote attacker
could trick a user, who was logged into the SWAT interface, into
visiting a specially crafted URL, it would lead to arbitrary web
script execution in the context of the user's SWAT session.
(CVE-2011-2694)

It was found that SWAT web pages did not protect against Cross-Site
Request Forgery (CSRF) attacks. If a remote attacker could trick a
user, who was logged into the SWAT interface, into visiting a
specially crafted URL, the attacker could perform Samba configuration
changes with the privileges of the logged in user. (CVE-2011-2522)

It was found that the fix for CVE-2010-0547, provided in the
cifs-utils package included in the GA release of Red Hat Enterprise
Linux 6, was incomplete. The mount.cifs tool did not properly handle
share or directory names containing a newline character, allowing a
local attacker to corrupt the mtab (mounted file systems table) file
via a specially crafted CIFS share mount request, if mount.cifs had
the setuid bit set. (CVE-2011-2724)

It was found that the mount.cifs tool did not handle certain errors
correctly when updating the mtab file. If mount.cifs had the setuid
bit set, a local attacker could corrupt the mtab file by setting a
small file size limit before running mount.cifs. (CVE-2011-1678)

Note: mount.cifs from the cifs-utils package distributed by Red Hat
does not have the setuid bit set. We recommend that administrators do
not manually set the setuid bit for mount.cifs.

Red Hat would like to thank the Samba project for reporting
CVE-2011-2694 and CVE-2011-2522, and Dan Rosenberg for reporting
CVE-2011-1678. Upstream acknowledges Nobuhiro Tsuji of NTT DATA
Security Corporation as the original reporter of CVE-2011-2694, and
Yoshihiro Ishikawa of LAC Co., Ltd. as the original reporter of
CVE-2011-2522.

This update also fixes the following bug :

* If plain text passwords were used ('encrypt passwords = no' in
'/etc/samba/smb.conf'), Samba clients running the Windows XP or
Windows Server 2003 operating system may not have been able to access
Samba shares after installing the Microsoft Security Bulletin
MS11-043. This update corrects this issue, allowing such clients to
use plain text passwords to access Samba shares. (BZ#728517)

Users of samba and cifs-utils are advised to upgrade to these updated
packages, which contain backported patches to resolve these issues.
After installing this update, the smb service will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-August/002315.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cifs-utils and / or samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cifs-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"cifs-utils-4.8.1-2.el6_1.2")) flag++;
if (rpm_check(release:"EL6", reference:"libsmbclient-3.5.6-86.el6_1.4")) flag++;
if (rpm_check(release:"EL6", reference:"libsmbclient-devel-3.5.6-86.el6_1.4")) flag++;
if (rpm_check(release:"EL6", reference:"samba-3.5.6-86.el6_1.4")) flag++;
if (rpm_check(release:"EL6", reference:"samba-client-3.5.6-86.el6_1.4")) flag++;
if (rpm_check(release:"EL6", reference:"samba-common-3.5.6-86.el6_1.4")) flag++;
if (rpm_check(release:"EL6", reference:"samba-doc-3.5.6-86.el6_1.4")) flag++;
if (rpm_check(release:"EL6", reference:"samba-domainjoin-gui-3.5.6-86.el6_1.4")) flag++;
if (rpm_check(release:"EL6", reference:"samba-swat-3.5.6-86.el6_1.4")) flag++;
if (rpm_check(release:"EL6", reference:"samba-winbind-3.5.6-86.el6_1.4")) flag++;
if (rpm_check(release:"EL6", reference:"samba-winbind-clients-3.5.6-86.el6_1.4")) flag++;
if (rpm_check(release:"EL6", reference:"samba-winbind-devel-3.5.6-86.el6_1.4")) flag++;
if (rpm_check(release:"EL6", reference:"samba-winbind-krb5-locator-3.5.6-86.el6_1.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cifs-utils / libsmbclient / libsmbclient-devel / samba / etc");
}
