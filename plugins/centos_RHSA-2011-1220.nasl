#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1220 and 
# CentOS Errata and Security Advisory 2011:1220 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(56272);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/05/19 23:52:00 $");

  script_cve_id("CVE-2010-0547", "CVE-2011-1678", "CVE-2011-2522", "CVE-2011-2694", "CVE-2011-2724");
  script_osvdb_id(74871);
  script_xref(name:"RHSA", value:"2011:1220");

  script_name(english:"CentOS 5 : samba3x (CESA-2011:1220)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated samba3x packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Samba is a suite of programs used by machines to share files,
printers, and other information.

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

It was found that the fix for CVE-2010-0547, provided by the Samba
rebase in RHBA-2011:0054, was incomplete. The mount.cifs tool did not
properly handle share or directory names containing a newline
character, allowing a local attacker to corrupt the mtab (mounted file
systems table) file via a specially crafted CIFS (Common Internet File
System) share mount request, if mount.cifs had the setuid bit set.
(CVE-2011-2724)

It was found that the mount.cifs tool did not handle certain errors
correctly when updating the mtab file. If mount.cifs had the setuid
bit set, a local attacker could corrupt the mtab file by setting a
small file size limit before running mount.cifs. (CVE-2011-1678)

Note: mount.cifs from the samba3x packages distributed by Red Hat does
not have the setuid bit set. We recommend that administrators do not
manually set the setuid bit for mount.cifs.

Red Hat would like to thank the Samba project for reporting
CVE-2011-2694 and CVE-2011-2522, and Dan Rosenberg for reporting
CVE-2011-1678. Upstream acknowledges Nobuhiro Tsuji of NTT DATA
Security Corporation as the original reporter of CVE-2011-2694, and
Yoshihiro Ishikawa of LAC Co., Ltd. as the original reporter of
CVE-2011-2522.

Users of Samba are advised to upgrade to these updated packages, which
contain backported patches to resolve these issues. After installing
this update, the smb service will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017970.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0720621c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017971.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4d1ac0e8"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000140.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4bded638"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000141.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0e2035ca"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba3x packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"samba3x-3.5.4-0.83.el5_7.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-client-3.5.4-0.83.el5_7.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-common-3.5.4-0.83.el5_7.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-doc-3.5.4-0.83.el5_7.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-domainjoin-gui-3.5.4-0.83.el5_7.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-swat-3.5.4-0.83.el5_7.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-winbind-3.5.4-0.83.el5_7.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-winbind-devel-3.5.4-0.83.el5_7.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
