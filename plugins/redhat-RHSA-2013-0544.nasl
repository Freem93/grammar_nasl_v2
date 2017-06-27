#
# (C) Tenable Network Security, Inc.
#
# Disabled on 2013/07/05.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0544. The text 
# itself is copyright (C) Red Hat, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(65172);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/05/02 20:36:57 $");

  script_cve_id("CVE-2012-5561", "CVE-2012-5603", "CVE-2012-5604", "CVE-2012-6109", "CVE-2012-6496", "CVE-2013-0162", "CVE-2013-0183", "CVE-2013-0184");
  script_osvdb_id(88140, 88142, 88661, 89317, 89320, 89327, 90561, 90577);
  script_xref(name:"RHSA", value:"2013:0544");

  script_name(english:"RHEL 6 : Subscription Asset Manager (RHSA-2013:0544)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Red Hat Subscription Asset Manager 1.2, which fixes several security
issues, multiple bugs, and adds various enhancements, is now
available.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Red Hat Subscription Asset Manager acts as a proxy for handling
subscription information and software updates on client machines.

It was discovered that Katello did not properly check user permissions
when handling certain requests. An authenticated remote attacker could
use this flaw to download consumer certificates or change settings of
other users' systems if they knew the target system's UUID.
(CVE-2012-5603)

A vulnerability in rubygem-ldap_fluff allowed a remote attacker to
bypass authentication and log into Subscription Asset Manager when a
Microsoft Active Directory server was used as the back-end
authentication server. (CVE-2012-5604)

It was found that the
'/usr/share/katello/script/katello-generate-passphrase' utility, which
is run during the installation and configuration process, set
world-readable permissions on the '/etc/katello/secure/passphrase'
file. A local attacker could use this flaw to obtain the passphrase
for Katello, giving them access to information they would otherwise
not have access to. (CVE-2012-5561)

Note: After installing this update, ensure the
'/etc/katello/secure/passphrase' file is owned by the root user and
group and mode 0750 permissions. Sites should also consider
re-creating the Katello passphrase as this issue exposed it to local
users.

Three flaws were found in rubygem-rack. A remote attacker could use
these flaws to perform a denial of service attack against applications
using rubygem-rack. (CVE-2012-6109, CVE-2013-0183, CVE-2013-0184)

A flaw was found in the way rubygem-activerecord dynamic finders
extracted options from method parameters. A remote attacker could
possibly use this flaw to perform SQL injection attacks against
applications using the Active Record dynamic finder methods.
(CVE-2012-6496)

It was found that ruby_parser from rubygem-ruby_parser created a
temporary file in an insecure way. A local attacker could use this
flaw to perform a symbolic link attack, overwriting arbitrary files
accessible to the application using ruby_parser. (CVE-2013-0162)

The CVE-2012-5603 issue was discovered by Lukas Zapletal of Red Hat;
CVE-2012-5604 was discovered by Og Maciel of Red Hat; CVE-2012-5561
was discovered by Aaron Weitekamp of the Red Hat Cloud Quality
Engineering team; and CVE-2013-0162 was discovered by Michael Scherer
of the Red Hat Regional IT team.

These updated Subscription Asset Manager packages include a number of
bug fixes and enhancements. Space precludes documenting all of these
changes in this advisory. Refer to the Red Hat Subscription Asset
Manager 1.2 Release Notes for information about these changes :

https://access.redhat.com/knowledge/docs/en-US/
Red_Hat_Subscription_Asset_Manager/1.2/html/Release_Notes/index.html

All users of Red Hat Subscription Asset Manager are advised to upgrade
to these updated packages, which fix these issues and add various
enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5561.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5603.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5604.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-6109.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-6496.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0162.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0183.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0184.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/knowledge/docs/en-US/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0544.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-codec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-codec-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-mime4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-mime4j-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-certs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-cli-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-configure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-glue-candlepin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-headpin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-headpin-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:lucene3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:lucene3-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppet-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:quartz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-activesupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-apipie-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ldap_fluff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mail-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ruby_parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ruby_parser-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sigar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sigar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sigar-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:snappy-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:snappy-java-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:thumbslug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:thumbslug-selinux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}

# Deprecated
exit(0, "This plugin has been temporarily deprecated.");

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (!rpm_exists(release:"RHEL6", rpm:"candlepin")) exit(0, "Red Hat Subscription Asset Manager is not installed.");

flag = 0;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"apache-commons-codec-1.7-2.el6_3")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"apache-commons-codec-debuginfo-1.7-2.el6_3")) flag++;
if (rpm_check(release:"RHEL6", reference:"apache-mime4j-0.6-4_redhat_1.ep6.el6.1")) flag++;
if (rpm_check(release:"RHEL6", reference:"apache-mime4j-javadoc-0.6-4_redhat_1.ep6.el6.1")) flag++;
if (rpm_check(release:"RHEL6", reference:"candlepin-0.7.23-1.el6_3")) flag++;
if (rpm_check(release:"RHEL6", reference:"candlepin-devel-0.7.23-1.el6_3")) flag++;
if (rpm_check(release:"RHEL6", reference:"candlepin-selinux-0.7.23-1.el6_3")) flag++;
if (rpm_check(release:"RHEL6", reference:"candlepin-tomcat6-0.7.23-1.el6_3")) flag++;
if (rpm_check(release:"RHEL6", reference:"elasticsearch-0.19.9-5.el6_3")) flag++;
if (rpm_check(release:"RHEL6", reference:"katello-certs-tools-1.2.1-1h.el6_3")) flag++;
if (rpm_check(release:"RHEL6", reference:"katello-cli-1.2.1-12h.el6_3")) flag++;
if (rpm_check(release:"RHEL6", reference:"katello-cli-common-1.2.1-12h.el6_3")) flag++;
if (rpm_check(release:"RHEL6", reference:"katello-common-1.2.1-15h.el6_3")) flag++;
if (rpm_check(release:"RHEL6", reference:"katello-configure-1.2.3-3h.el6_3")) flag++;
if (rpm_check(release:"RHEL6", reference:"katello-glue-candlepin-1.2.1-15h.el6_3")) flag++;
if (rpm_check(release:"RHEL6", reference:"katello-headpin-1.2.1-15h.el6_3")) flag++;
if (rpm_check(release:"RHEL6", reference:"katello-headpin-all-1.2.1-15h.el6_3")) flag++;
if (rpm_check(release:"RHEL6", reference:"katello-selinux-1.2.1-2h.el6_3")) flag++;
if (rpm_check(release:"RHEL6", reference:"lucene3-3.6.1-10h.el6_3")) flag++;
if (rpm_check(release:"RHEL6", reference:"lucene3-contrib-3.6.1-10h.el6_3")) flag++;
if (rpm_check(release:"RHEL6", reference:"puppet-2.6.17-2.el6cf")) flag++;
if (rpm_check(release:"RHEL6", reference:"puppet-server-2.6.17-2.el6cf")) flag++;
if (rpm_check(release:"RHEL6", reference:"quartz-2.1.5-4.el6_3")) flag++;
if (rpm_check(release:"RHEL6", reference:"rubygem-activesupport-3.0.10-10.el6cf")) flag++;
if (rpm_check(release:"RHEL6", reference:"rubygem-apipie-rails-0.0.12-2.el6cf")) flag++;
if (rpm_check(release:"RHEL6", reference:"rubygem-ldap_fluff-0.1.3-1.el6_3")) flag++;
if (rpm_check(release:"RHEL6", reference:"rubygem-mail-2.3.0-3.el6cf")) flag++;
if (rpm_check(release:"RHEL6", reference:"rubygem-mail-doc-2.3.0-3.el6cf")) flag++;
if (rpm_check(release:"RHEL6", reference:"rubygem-ruby_parser-2.0.4-6.el6cf")) flag++;
if (rpm_check(release:"RHEL6", reference:"rubygem-ruby_parser-doc-2.0.4-6.el6cf")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sigar-1.6.5-0.12.git58097d9h.el6_3")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sigar-debuginfo-1.6.5-0.12.git58097d9h.el6_3")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sigar-java-1.6.5-0.12.git58097d9h.el6_3")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"snappy-java-1.0.4-2.el6_3")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"snappy-java-debuginfo-1.0.4-2.el6_3")) flag++;
if (rpm_check(release:"RHEL6", reference:"thumbslug-0.0.28-1.el6_3")) flag++;
if (rpm_check(release:"RHEL6", reference:"thumbslug-selinux-0.0.28-1.el6_3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
