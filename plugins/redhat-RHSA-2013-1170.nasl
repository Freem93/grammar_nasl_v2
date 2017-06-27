#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1170. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76662);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/05 16:29:43 $");

  script_cve_id("CVE-2013-1892", "CVE-2013-2132");
  script_bugtraq_id(58695, 60252);
  script_osvdb_id(91632, 93804, 95507);
  script_xref(name:"RHSA", value:"2013:1170");

  script_name(english:"RHEL 6 : MRG (RHSA-2013:1170)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mongodb and pymongo packages that fix two security issues and
add one enhancement are now available for Red Hat Enterprise MRG 2.3
for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

MongoDB is a NoSQL database. PyMongo provides tools for working with
MongoDB.

A flaw was found in the run() function implementation in MongoDB. A
database user permitted to send database queries to a MongoDB server
could use this flaw to crash the server or, possibly, execute
arbitrary code with the privileges of the mongodb user.
(CVE-2013-1892)

A NULL pointer dereference flaw was found in PyMongo. An invalid DBRef
record received from a MongoDB server could cause an application using
PyMongo to crash. (CVE-2013-2132)

Note: In Red Hat Enterprise MRG Grid, MongoDB is not accessed by users
directly and is only accessed by other Grid services, such as Condor
and Cumin.

This update also adds the following enhancement :

* Previously, MongoDB was configured to listen for connections on all
network interfaces. This could allow remote users to access the
database if the firewall was configured to allow access to the MongoDB
port (access is blocked by the default firewall configuration in Red
Hat Enterprise Linux). This update changes the configuration to only
listen on the loopback interface by default. (BZ#892767)

Users of Red Hat Enterprise MRG 2.3 for Red Hat Enterprise Linux 6 are
advised to upgrade to these updated packages, which contain backported
patches to resolve these issues and add this enhancement. After
installing this update, MongoDB will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1892.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2132.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1170.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MongoDB nativeHelper.apply Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mongodb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mongodb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mongodb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pymongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pymongo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-bson");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/21");
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
  rhsa = "RHSA-2013:1170";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mongodb-1.6.4-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mongodb-1.6.4-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mongodb-debuginfo-1.6.4-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mongodb-debuginfo-1.6.4-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mongodb-server-1.6.4-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mongodb-server-1.6.4-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pymongo-1.9-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pymongo-1.9-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pymongo-debuginfo-1.9-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pymongo-debuginfo-1.9-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-bson-1.9-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-bson-1.9-11.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mongodb / mongodb-debuginfo / mongodb-server / pymongo / etc");
  }
}
