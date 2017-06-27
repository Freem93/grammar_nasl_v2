#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1278. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76649);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/05 16:17:29 $");

  script_cve_id("CVE-2012-2680", "CVE-2012-2681", "CVE-2012-2683", "CVE-2012-2684", "CVE-2012-2685", "CVE-2012-2734", "CVE-2012-2735", "CVE-2012-3459", "CVE-2012-3491", "CVE-2012-3492", "CVE-2012-3493");
  script_bugtraq_id(55632);
  script_osvdb_id(85668, 85669, 85670, 85671, 85672, 85673, 85674, 85675, 85676, 85677, 85678);
  script_xref(name:"RHSA", value:"2012:1278");

  script_name(english:"RHEL 5 : MRG (RHSA-2012:1278)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Grid component packages that fix several security issues, add
various enhancements and fix multiple bugs are now available for Red
Hat Enterprise MRG 2 for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Red Hat Enterprise MRG (Messaging, Realtime, and Grid) is a
next-generation IT infrastructure for enterprise computing. MRG offers
increased performance, reliability, interoperability, and faster
computing for enterprise customers.

A number of unprotected resources (web pages, export functionality,
image viewing) were found in Cumin. An unauthenticated user could
bypass intended access restrictions, resulting in information
disclosure. (CVE-2012-2680)

Cumin could generate weak session keys, potentially allowing remote
attackers to predict session keys and obtain unauthorized access to
Cumin. (CVE-2012-2681)

Multiple cross-site scripting flaws in Cumin could allow remote
attackers to inject arbitrary web script on a web page displayed by
Cumin. (CVE-2012-2683)

A SQL injection flaw in Cumin could allow remote attackers to
manipulate the contents of the back-end database via a specially
crafted URL. (CVE-2012-2684)

When Cumin handled image requests, clients could request images of
arbitrary sizes. This could result in large memory allocations on the
Cumin server, leading to an out-of-memory condition. (CVE-2012-2685)

Cumin did not protect against Cross-Site Request Forgery attacks. If
an attacker could trick a user, who was logged into the Cumin web
interface, into visiting a specially crafted web page, it could lead
to unauthorized command execution in the Cumin web interface with the
privileges of the logged-in user. (CVE-2012-2734)

A session fixation flaw was found in Cumin. An authenticated user able
to pre-set the Cumin session cookie in a victim's browser could
possibly use this flaw to steal the victim's session after they log
into Cumin. (CVE-2012-2735)

It was found that authenticated users could send a specially crafted
HTTP POST request to Cumin that would cause it to submit a job
attribute change to Condor. This could be used to change internal
Condor attributes, including the Owner attribute, which could allow
Cumin users to elevate their privileges. (CVE-2012-3459)

It was discovered that Condor's file system authentication challenge
accepted directories with weak permissions (for example, world
readable, writable and executable permissions). If a user created a
directory with such permissions, a local attacker could rename it,
allowing them to execute jobs with the privileges of the victim user.
(CVE-2012-3492)

It was discovered that Condor exposed private information in the data
in the ClassAds format served by condor_startd. An unauthenticated
user able to connect to condor_startd's port could request a ClassAd
for a running job, provided they could guess or brute-force the PID of
the job. This could expose the ClaimId which, if obtained, could be
used to control the job as well as start new jobs on the system.
(CVE-2012-3493)

It was discovered that the ability to abort a job in Condor only
required WRITE authorization, instead of a combination of WRITE
authorization and job ownership. This could allow an authenticated
attacker to bypass intended restrictions and abort any idle job on the
system. (CVE-2012-3491)

The above issues were discovered by Florian Weimer of the Red Hat
Product Security Team.

This update also provides defense in depth patches for Condor.
(BZ#848212, BZ#835592, BZ#841173, BZ#843476)

These updated packages for Red Hat Enterprise Linux 5 provide numerous
enhancements and bug fixes for the Grid component of MRG. Some
highlights include :

* Integration with Red Hat Enterprise Virtualization Manager via
Deltacloud * Role enforcement in Cumin * Cumin authentication
integration with LDAP * Enhanced Red Hat HA integration managing
multiple-schedulers nodes * Generic local resource limits for
partitionable slots * Concurrency limit groups

Space precludes documenting all of these changes in this advisory.
Refer to the Red Hat Enterprise MRG 2 Technical Notes document, linked
to in the References section, for information on these changes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2680.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2681.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2683.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2684.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2685.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2734.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2735.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3459.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3491.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3492.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3493.html"
  );
  # https://access.redhat.com/knowledge/docs/en-US/Red_Hat_Enterprise_MRG/2/html/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?385bfeb4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-1278.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-aviary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-classads");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-kbdd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-vm-gahp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-wallaby-base-db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-wallaby-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-wallaby-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cumin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-wallaby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-wallabyclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-wallaby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sesame");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wallaby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wallaby-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:1278";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;

  if (! (rpm_exists(release:"RHEL5", rpm:"mrg-release"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "MRG");

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"condor-7.6.5-0.22.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"condor-7.6.5-0.22.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"condor-aviary-7.6.5-0.22.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"condor-aviary-7.6.5-0.22.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"condor-classads-7.6.5-0.22.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"condor-classads-7.6.5-0.22.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"condor-kbdd-7.6.5-0.22.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"condor-kbdd-7.6.5-0.22.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"condor-qmf-7.6.5-0.22.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"condor-qmf-7.6.5-0.22.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"condor-vm-gahp-7.6.5-0.22.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"condor-vm-gahp-7.6.5-0.22.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"condor-wallaby-base-db-1.23-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"condor-wallaby-client-4.1.3-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"condor-wallaby-tools-4.1.3-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"cumin-0.1.5444-3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"python-wallaby-0.12.5-10.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"python-wallabyclient-4.1.3-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ruby-wallaby-0.12.5-10.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sesame-1.0-4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sesame-1.0-4.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"wallaby-0.12.5-10.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"wallaby-utils-0.12.5-10.el5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "condor / condor-aviary / condor-classads / condor-kbdd / condor-qmf / etc");
  }
}
