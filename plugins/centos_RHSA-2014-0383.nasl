#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0383 and 
# CentOS Errata and Security Advisory 2014:0383 respectively.
#

include("compat.inc");

if (description)
{
  script_id(73464);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/04 14:39:52 $");

  script_cve_id("CVE-2012-6150", "CVE-2013-4496", "CVE-2013-6442");
  script_bugtraq_id(64101, 66232, 66336);
  script_osvdb_id(102653, 104374);
  script_xref(name:"RHSA", value:"2014:0383");

  script_name(english:"CentOS 6 : samba4 (CESA-2014:0383)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated samba4 packages that fix three security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) or Common Internet File System (CIFS) protocol, which allows
PC-compatible machines to share files, printers, and other
information.

It was found that certain Samba configurations did not enforce the
password lockout mechanism. A remote attacker could use this flaw to
perform password guessing attacks on Samba user accounts. Note: this
flaw only affected Samba when deployed as a Primary Domain Controller.
(CVE-2013-4496)

A flaw was found in Samba's 'smbcacls' command, which is used to set
or get ACLs on SMB file shares. Certain command line options of this
command would incorrectly remove an ACL previously applied on a file
or a directory, leaving the file or directory without the intended
ACL. (CVE-2013-6442)

A flaw was found in the way the pam_winbind module handled
configurations that specified a non-existent group as required. An
authenticated user could possibly use this flaw to gain access to a
service using pam_winbind in its PAM configuration when group
restriction was intended for access to the service. (CVE-2012-6150)

Red Hat would like to thank the Samba project for reporting
CVE-2013-4496 and CVE-2013-6442, and Sam Richardson for reporting
CVE-2012-6150. Upstream acknowledges Andrew Bartlett as the original
reporter of CVE-2013-4496, and Noel Power as the original reporter of
CVE-2013-6442.

All users of Samba are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing this update, the smb service will be restarted
automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-April/020250.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0476634f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba4 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"samba4-4.0.0-61.el6_5.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-client-4.0.0-61.el6_5.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-common-4.0.0-61.el6_5.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-dc-4.0.0-61.el6_5.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-dc-libs-4.0.0-61.el6_5.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-devel-4.0.0-61.el6_5.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-libs-4.0.0-61.el6_5.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-pidl-4.0.0-61.el6_5.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-python-4.0.0-61.el6_5.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-swat-4.0.0-61.el6_5.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-test-4.0.0-61.el6_5.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-winbind-4.0.0-61.el6_5.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-winbind-clients-4.0.0-61.el6_5.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-winbind-krb5-locator-4.0.0-61.el6_5.rc4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
