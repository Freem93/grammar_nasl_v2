#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1281. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76651);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/05 16:17:29 $");

  script_cve_id("CVE-2012-2680", "CVE-2012-2681", "CVE-2012-2683", "CVE-2012-2684", "CVE-2012-2685", "CVE-2012-2734", "CVE-2012-2735", "CVE-2012-3459", "CVE-2012-3491", "CVE-2012-3492", "CVE-2012-3493");
  script_bugtraq_id(55632);
  script_osvdb_id(85668, 85669, 85670, 85671, 85672, 85673, 85674, 85675, 85676, 85677, 85678);
  script_xref(name:"RHSA", value:"2012:1281");

  script_name(english:"RHEL 6 : MRG (RHSA-2012:1281)");
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
Hat Enterprise MRG 2 for Red Hat Enterprise Linux 6.

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

These updated packages for Red Hat Enterprise Linux 6 provide numerous
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
    value:"http://rhn.redhat.com/errata/RHSA-2012-1281.html"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-cluster-resource-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-deltacloud-gahp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-kbdd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-plumage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-vm-gahp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-wallaby-base-db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-wallaby-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-wallaby-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cumin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:deltacloud-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:deltacloud-core-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:deltacloud-core-rhevm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdeltacloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdeltacloud-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdeltacloud-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-wallaby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-wallabyclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-hpricot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-nokogiri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-wallaby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-eventmachine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-eventmachine-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fssm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-haml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hpricot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hpricot-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hpricot-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-json-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-maruku");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mime-types");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mime-types-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mocha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-net-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-net-ssh-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-nokogiri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-nokogiri-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-nokogiri-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack-accept");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack-accept-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rest-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-sass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-sass-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-sinatra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-syntax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-thin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-thin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-thin-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-tilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-tilt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-yard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sesame");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sesame-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wallaby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wallaby-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:1281";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"mrg-release"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "MRG");

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-7.6.5-0.22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-7.6.5-0.22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-aviary-7.6.5-0.22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-aviary-7.6.5-0.22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-classads-7.6.5-0.22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-classads-7.6.5-0.22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-cluster-resource-agent-7.6.5-0.22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-cluster-resource-agent-7.6.5-0.22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-debuginfo-7.6.5-0.22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-debuginfo-7.6.5-0.22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-deltacloud-gahp-7.6.5-0.22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-kbdd-7.6.5-0.22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-kbdd-7.6.5-0.22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-plumage-7.6.5-0.22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-plumage-7.6.5-0.22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-qmf-7.6.5-0.22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-qmf-7.6.5-0.22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-vm-gahp-7.6.5-0.22.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"condor-wallaby-base-db-1.23-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"condor-wallaby-client-4.1.3-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"condor-wallaby-tools-4.1.3-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"cumin-0.1.5444-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"deltacloud-core-0.5.0-10.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", reference:"deltacloud-core-doc-0.5.0-10.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", reference:"deltacloud-core-rhevm-0.5.0-10.el6_2")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libdeltacloud-0.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libdeltacloud-debuginfo-0.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libdeltacloud-devel-0.9-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-wallaby-0.12.5-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-wallabyclient-4.1.3-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby-hpricot-0.8.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby-json-1.4.6-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby-nokogiri-1.5.0-0.8.beta4.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby-wallaby-0.12.5-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-daemons-1.1.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-eventmachine-0.12.10-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-eventmachine-debuginfo-0.12.10-7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-fssm-0.2.7-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-haml-3.1.2-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-hpricot-0.8.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-hpricot-debuginfo-0.8.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-hpricot-doc-0.8.4-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-json-1.4.6-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-json-debuginfo-1.4.6-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-maruku-0.6.0-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-mime-types-1.16-4.el6_0")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-mime-types-doc-1.16-4.el6_0")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-mocha-0.9.7-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-net-ssh-2.0.23-6.el6_0")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-net-ssh-doc-2.0.23-6.el6_0")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-nokogiri-1.5.0-0.8.beta4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-nokogiri-debuginfo-1.5.0-0.8.beta4.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-nokogiri-doc-1.5.0-0.8.beta4.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-rack-1.3.0-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-rack-accept-0.4.3-6.el6_0")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-rack-accept-doc-0.4.3-6.el6_0")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-rack-test-0.6.1-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-rake-0.8.7-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-rest-client-1.6.1-2.el6_0")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-sass-3.1.4-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-sass-doc-3.1.4-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-sinatra-1.2.6-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-syntax-1.0.0-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-thin-1.2.11-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-thin-debuginfo-1.2.11-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-thin-doc-1.2.11-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-tilt-1.3.2-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-tilt-doc-1.3.2-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-yard-0.7.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygems-1.8.16-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"sesame-1.0-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sesame-1.0-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"sesame-debuginfo-1.0-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sesame-debuginfo-1.0-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"wallaby-0.12.5-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"wallaby-utils-0.12.5-10.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "condor / condor-aviary / condor-classads / etc");
  }
}
