#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0528 and 
# CentOS Errata and Security Advisory 2013:0528 respectively.
#

include("compat.inc");

if (description)
{
  script_id(65157);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/05/19 23:52:01 $");

  script_cve_id("CVE-2012-4546");
  script_bugtraq_id(58083);
  script_xref(name:"RHSA", value:"2013:0528");

  script_name(english:"CentOS 6 : ipa (CESA-2013:0528)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ipa packages that fix one security issue, several bugs, and
add various enhancements are now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Red Hat Identity Management is a centralized authentication, identity
management and authorization solution for both traditional and
cloud-based enterprise environments. It integrates components of the
Red Hat Directory Server, MIT Kerberos, Red Hat Certificate System,
NTP, and DNS. It provides web browser and command-line interfaces. Its
administration tools allow an administrator to quickly install, set
up, and administer a group of domain controllers to meet the
authentication and identity management requirements of large-scale
Linux and UNIX deployments.

It was found that the current default configuration of IPA servers did
not publish correct CRLs (Certificate Revocation Lists). The default
configuration specifies that every replica is to generate its own CRL;
however, this can result in inconsistencies in the CRL contents
provided to clients from different Identity Management replicas. More
specifically, if a certificate is revoked on one Identity Management
replica, it will not show up on another Identity Management replica.
(CVE-2012-4546)

These updated ipa packages also include numerous bug fixes and
enhancements. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 6.4
Technical Notes, linked to in the References, for information on the
most significant of these changes.

Users are advised to upgrade to these updated ipa packages, which fix
these issues and add these enhancements."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-March/019353.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f1afa50"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-February/000542.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e87c6f8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ipa packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-admintools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"ipa-admintools-3.0.0-25.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ipa-client-3.0.0-25.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ipa-python-3.0.0-25.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ipa-server-3.0.0-25.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ipa-server-selinux-3.0.0-25.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ipa-server-trust-ad-3.0.0-25.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
