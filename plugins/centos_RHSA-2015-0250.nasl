#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0250 and 
# CentOS Errata and Security Advisory 2015:0250 respectively.
#

include("compat.inc");

if (description)
{
  script_id(81441);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/04 14:39:53 $");

  script_cve_id("CVE-2015-0240");
  script_bugtraq_id(72711);
  script_osvdb_id(118637);
  script_xref(name:"RHSA", value:"2015:0250");

  script_name(english:"CentOS 6 : samba4 (CESA-2015:0250)");
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

Red Hat Product Security has rated this update as having Critical
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) or Common Internet File System (CIFS) protocol, which allows
PC-compatible machines to share files, printers, and other
information.

An uninitialized pointer use flaw was found in the Samba daemon
(smbd). A malicious Samba client could send specially crafted netlogon
packets that, when processed by smbd, could potentially lead to
arbitrary code execution with the privileges of the user running smbd
(by default, the root user). (CVE-2015-0240)

For additional information about this flaw, see the Knowledgebase
article at https://access.redhat.com/articles/1346913

Red Hat would like to thank the Samba project for reporting this
issue. Upstream acknowledges Richard van Eeden of Microsoft
Vulnerability Research as the original reporter of this issue.

All Samba users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. After
installing this update, the smb service will be restarted
automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-February/020944.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1315c7a5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba4 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"samba4-4.0.0-66.el6_6.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-client-4.0.0-66.el6_6.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-common-4.0.0-66.el6_6.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-dc-4.0.0-66.el6_6.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-dc-libs-4.0.0-66.el6_6.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-devel-4.0.0-66.el6_6.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-libs-4.0.0-66.el6_6.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-pidl-4.0.0-66.el6_6.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-python-4.0.0-66.el6_6.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-swat-4.0.0-66.el6_6.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-test-4.0.0-66.el6_6.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-winbind-4.0.0-66.el6_6.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-winbind-clients-4.0.0-66.el6_6.rc4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-winbind-krb5-locator-4.0.0-66.el6_6.rc4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
