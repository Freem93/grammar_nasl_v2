#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0001 and 
# CentOS Errata and Security Advisory 2017:0001 respectively.
#

include("compat.inc");

if (description)
{
  script_id(96182);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/01/10 18:05:12 $");

  script_cve_id("CVE-2016-7030", "CVE-2016-9575");
  script_osvdb_id(148787, 148788);
  script_xref(name:"RHSA", value:"2017:0001");

  script_name(english:"CentOS 7 : ipa (CESA-2017:0001)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for ipa is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat Identity Management (IdM) is a centralized authentication,
identity management, and authorization solution for both traditional
and cloud-based enterprise environments.

Security Fix(es) :

* It was discovered that the default IdM password policies that lock
out accounts after a certain number of failed login attempts were also
applied to host and service accounts. A remote unauthenticated user
could use this flaw to cause a denial of service attack against
kerberized services. (CVE-2016-7030)

* It was found that IdM's certprofile-mod command did not properly
check the user's permissions while modifying certificate profiles. An
authenticated, unprivileged attacker could use this flaw to modify
profiles to issue certificates with arbitrary naming or key usage
information and subsequently use such certificates for other attacks.
(CVE-2016-9575)

The CVE-2016-7030 issue was discovered by Petr Spacek (Red Hat) and
the CVE-2016-9575 issue was discovered by Liam Campbell (Red Hat)."
  );
  # http://lists.centos.org/pipermail/centos-announce/2017-January/022190.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a2adba7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ipa packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-admintools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-python-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-ipaclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-ipalib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-ipaserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-admintools-4.4.0-14.el7.centos.1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-client-4.4.0-14.el7.centos.1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-client-common-4.4.0-14.el7.centos.1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-common-4.4.0-14.el7.centos.1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-python-compat-4.4.0-14.el7.centos.1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-server-4.4.0-14.el7.centos.1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-server-common-4.4.0-14.el7.centos.1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-server-dns-4.4.0-14.el7.centos.1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-server-trust-ad-4.4.0-14.el7.centos.1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python2-ipaclient-4.4.0-14.el7.centos.1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python2-ipalib-4.4.0-14.el7.centos.1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python2-ipaserver-4.4.0-14.el7.centos.1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
