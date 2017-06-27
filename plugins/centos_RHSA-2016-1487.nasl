#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1487 and 
# CentOS Errata and Security Advisory 2016:1487 respectively.
#

include("compat.inc");

if (description)
{
  script_id(92567);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/12/27 14:39:36 $");

  script_cve_id("CVE-2016-2119");
  script_osvdb_id(141072);
  script_xref(name:"RHSA", value:"2016:1487");

  script_name(english:"CentOS 6 : samba4 (CESA-2016:1487)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for samba4 is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) or Common Internet File System (CIFS) protocol, which allows
PC-compatible machines to share files, printers, and other
information.

Security Fix(es) :

* A flaw was found in the way Samba initiated signed DCE/RPC
connections. A man-in-the-middle attacker could use this flaw to
downgrade the connection to not use signing and therefore impersonate
the server. (CVE-2016-2119)

Red Hat would like to thank the Samba project for reporting this
issue. Upstream acknowledges Stefan Metzmacher as the original
reporter."
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-July/021994.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?86ec90c2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba4 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba4-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"samba4-4.2.10-7.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-client-4.2.10-7.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-common-4.2.10-7.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-dc-4.2.10-7.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-dc-libs-4.2.10-7.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-devel-4.2.10-7.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-libs-4.2.10-7.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-pidl-4.2.10-7.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-python-4.2.10-7.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-test-4.2.10-7.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-winbind-4.2.10-7.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-winbind-clients-4.2.10-7.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba4-winbind-krb5-locator-4.2.10-7.el6_8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
