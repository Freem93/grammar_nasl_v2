#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1042. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67239);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/05 16:29:43 $");

  script_cve_id("CVE-2013-2165");
  script_bugtraq_id(61085);
  script_osvdb_id(95159);
  script_xref(name:"RHSA", value:"2013:1042");

  script_name(english:"RHEL 4 / 5 / 6 : richfaces (RHSA-2013:1042)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated richfaces packages that fix one security issue are now
available for Red Hat JBoss Enterprise Application Platform 5.2.0 for
Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

RichFaces is an open source framework that adds Ajax capability into
existing JavaServer Faces (JSF) applications.

A flaw was found in the way RichFaces ResourceBuilderImpl handled
deserialization. A remote attacker could use this flaw to trigger the
execution of the deserialization methods in any serializable class
deployed on the server. This could lead to a variety of security
impacts depending on the deserialization logic of these classes.
(CVE-2013-2165)

The fix for this issue introduces a whitelist to limit classes that
can be deserialized by RichFaces.

If you require to whitelist a class that is not already listed, for
example, a custom class, you can achieve this by following one of
these methods :

Method 1: Implementing the SerializableResource interface. In
RichFaces 3, this is defined at
org.ajax4jsf.resource.SerializableResource and in RichFaces 4/5, at
org.richfaces.resource.SerializableResource.

Method 2: Adding the class to the resource-serialization.properties
file (a default properties file is provided once this update is
applied). To do this you can extend the framework provided properties
file that is available under org.ajax4jsf.resource in RichFaces 3 and
org.richfaces.resource in RichFaces 4/5. The modified properties file
has to be copied into the classpath of your deployment under the
version-specific packages.

Where possible, it is recommended that Method 1 be followed.

Red Hat would like to thank Takeshi Terada (Mitsui Bussan Secure
Directions, Inc.) for reporting this issue.

Warning: Before applying this update, back up your existing Red Hat
JBoss Enterprise Application Platform installation (including all
applications and configuration files).

All users of Red Hat JBoss Enterprise Application Platform 5.2.0 on
Red Hat Enterprise Linux 4, 5, and 6 are advised to upgrade to these
updated packages. The JBoss server process must be restarted for the
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2165.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1042.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:richfaces");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:richfaces-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:richfaces-framework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:richfaces-root");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:richfaces-ui");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4|5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:1042";
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
  if (rpm_check(release:"RHEL4", reference:"richfaces-3.3.1-11.SP3_patch_01.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"richfaces-demo-3.3.1-11.SP3_patch_01.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"richfaces-framework-3.3.1-11.SP3_patch_01.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"richfaces-root-3.3.1-11.SP3_patch_01.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"richfaces-ui-3.3.1-11.SP3_patch_01.ep5.el4")) flag++;

  if (rpm_check(release:"RHEL5", reference:"richfaces-3.3.1-6.SP3_patch_01.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"richfaces-demo-3.3.1-6.SP3_patch_01.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"richfaces-framework-3.3.1-6.SP3_patch_01.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"richfaces-root-3.3.1-6.SP3_patch_01.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"richfaces-ui-3.3.1-6.SP3_patch_01.ep5.el5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"richfaces-3.3.1-3.SP3_patch_01.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"richfaces-demo-3.3.1-3.SP3_patch_01.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"richfaces-framework-3.3.1-3.SP3_patch_01.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"richfaces-root-3.3.1-3.SP3_patch_01.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"richfaces-ui-3.3.1-3.SP3_patch_01.ep5.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "richfaces / richfaces-demo / richfaces-framework / richfaces-root / etc");
  }
}
