#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0330 and 
# CentOS Errata and Security Advisory 2014:0330 respectively.
#

include("compat.inc");

if (description)
{
  script_id(73192);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/04 14:39:52 $");

  script_cve_id("CVE-2012-6150", "CVE-2013-4496");
  script_bugtraq_id(64101, 66336);
  script_osvdb_id(102653, 104374);
  script_xref(name:"RHSA", value:"2014:0330");

  script_name(english:"CentOS 5 / 6 : samba / samba3x (CESA-2014:0330)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated samba3x and samba packages that fix two security issues are
now available for Red Hat Enterprise Linux 5 and 6 respectively.

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

A flaw was found in the way the pam_winbind module handled
configurations that specified a non-existent group as required. An
authenticated user could possibly use this flaw to gain access to a
service using pam_winbind in its PAM configuration when group
restriction was intended for access to the service. (CVE-2012-6150)

Red Hat would like to thank the Samba project for reporting
CVE-2013-4496 and Sam Richardson for reporting CVE-2012-6150. Upstream
acknowledges Andrew Bartlett as the original reporter of
CVE-2013-4496.

All users of Samba are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing this update, the smb service will be restarted
automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-March/020228.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?69e4f155"
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-March/020232.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?529ee9d8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba and / or samba3x packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/26");
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
if (rpm_check(release:"CentOS-5", reference:"samba3x-3.6.6-0.139.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-client-3.6.6-0.139.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-common-3.6.6-0.139.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-doc-3.6.6-0.139.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-domainjoin-gui-3.6.6-0.139.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-swat-3.6.6-0.139.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-winbind-3.6.6-0.139.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-winbind-devel-3.6.6-0.139.el5_10")) flag++;

if (rpm_check(release:"CentOS-6", reference:"libsmbclient-3.6.9-168.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsmbclient-devel-3.6.9-168.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-3.6.9-168.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-client-3.6.9-168.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-common-3.6.9-168.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-doc-3.6.9-168.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-domainjoin-gui-3.6.9-168.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-swat-3.6.9-168.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-winbind-3.6.9-168.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-winbind-clients-3.6.9-168.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-winbind-devel-3.6.9-168.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"samba-winbind-krb5-locator-3.6.9-168.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
