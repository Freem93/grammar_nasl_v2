#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1009 and 
# CentOS Errata and Security Advisory 2014:1009 respectively.
#

include("compat.inc");

if (description)
{
  script_id(77006);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/04/27 16:14:32 $");

  script_cve_id("CVE-2014-0178", "CVE-2014-0244", "CVE-2014-3493", "CVE-2014-3560");
  script_bugtraq_id(69021);
  script_xref(name:"RHSA", value:"2014:1009");

  script_name(english:"CentOS 6 : samba4 (CESA-2014:1009)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated samba4 packages that fix one security issue are now available
for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
Important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) or Common Internet File System (CIFS) protocol, which allows
PC-compatible machines to share files, printers, and other
information.

A heap-based buffer overflow flaw was found in Samba's NetBIOS message
block daemon (nmbd). An attacker on the local network could use this
flaw to send specially crafted packets that, when processed by nmbd,
could possibly lead to arbitrary code execution with root privileges.
(CVE-2014-3560)

All Samba users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. After
installing this update, the smb service will be restarted
automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-August/020465.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f7ffec6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba4 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/06");
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
if (rpm_check(release:"CentOS-6", reference:"samba4-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-client-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-common-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-dc-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-dc-libs-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-devel-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-libs-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-pidl-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-python-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-swat-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-test-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-winbind-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-winbind-clients-4.0.0-63.el6_5.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-winbind-krb5-locator-4.0.0-63.el6_5.rc4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
