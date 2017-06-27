#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1299. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63999);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/08/18 18:39:01 $");

  script_cve_id("CVE-2011-1594", "CVE-2011-2919", "CVE-2011-2920", "CVE-2011-2927", "CVE-2011-3344");
  script_osvdb_id(74749);
  script_xref(name:"RHSA", value:"2011:1299");

  script_name(english:"RHEL 5 / 6 : Satellite Server (RHSA-2011:1299)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated packages that fix several security issues and add one
enhancement are now available for Red Hat Network Satellite 5.4.1 for
Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Red Hat Network (RHN) Satellite provides a solution to organizations
requiring absolute control over and privacy of the maintenance and
package deployment of their servers. It allows organizations to
utilize the benefits of the Red Hat Network without having to provide
public Internet access to their servers or other client systems.

Multiple cross-site scripting (XSS) flaws were found in the RHN
Satellite web interface. A remote attacker could use these flaws to
perform a cross-site scripting attack against victims using the RHN
Satellite web interface. (CVE-2011-2919, CVE-2011-2920, CVE-2011-2927,
CVE-2011-3344)

An open redirect flaw was found in the RHN Satellite web interface
login page. A remote attacker able to trick a victim to open the login
page using a specially crafted link could redirect the victim to an
arbitrary page after they successfully log in. (CVE-2011-1594)

Red Hat would like to thank Daniel Karanja Muturi for reporting
CVE-2011-2919; Nils Juenemann and The Bearded Warriors for
independently reporting CVE-2011-2920; Nils Juenemann for reporting
CVE-2011-2927; Sylvain Maes for reporting CVE-2011-3344; and Thomas
Biege of the SuSE Security Team for reporting CVE-2011-1594.

This update also adds the following enhancement :

* Session cookies set by RHN Satellite are now marked as HTTPOnly.
This setting helps reduce the impact of cross-site scripting flaws by
instructing the browser to disallow scripts access to those cookies.
(BZ#713477)

Users of Red Hat Network Satellite 5.4.1 are advised to upgrade to
these updated packages, which contain patches to correct these issues
and add this enhancement. For this update to take effect, Red Hat
Network Satellite must be restarted. Refer to the Solution section for
details."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1594.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2919.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2920.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2927.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3344.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1299.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-base-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-dobby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-grail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-pxt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-sniglets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-taskomatic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


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

flag = 0;
if (rpm_check(release:"RHEL5", reference:"spacewalk-base-1.2.7-20.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-base-minimal-1.2.7-20.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-config-1.2.2-7.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-dobby-1.2.7-20.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-grail-1.2.7-20.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-html-1.2.7-20.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-java-1.2.39-98.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-java-config-1.2.39-98.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-java-lib-1.2.39-98.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-java-oracle-1.2.39-98.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-pxt-1.2.7-20.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-sniglets-1.2.7-20.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-taskomatic-1.2.39-98.el5sat")) flag++;

if (rpm_check(release:"RHEL6", reference:"spacewalk-base-1.2.7-20.el6sat")) flag++;
if (rpm_check(release:"RHEL6", reference:"spacewalk-base-minimal-1.2.7-20.el6sat")) flag++;
if (rpm_check(release:"RHEL6", reference:"spacewalk-config-1.2.2-7.el6sat")) flag++;
if (rpm_check(release:"RHEL6", reference:"spacewalk-dobby-1.2.7-20.el6sat")) flag++;
if (rpm_check(release:"RHEL6", reference:"spacewalk-grail-1.2.7-20.el6sat")) flag++;
if (rpm_check(release:"RHEL6", reference:"spacewalk-html-1.2.7-20.el6sat")) flag++;
if (rpm_check(release:"RHEL6", reference:"spacewalk-java-1.2.39-98.el6sat")) flag++;
if (rpm_check(release:"RHEL6", reference:"spacewalk-java-config-1.2.39-98.el6sat")) flag++;
if (rpm_check(release:"RHEL6", reference:"spacewalk-java-lib-1.2.39-98.el6sat")) flag++;
if (rpm_check(release:"RHEL6", reference:"spacewalk-java-oracle-1.2.39-98.el6sat")) flag++;
if (rpm_check(release:"RHEL6", reference:"spacewalk-pxt-1.2.7-20.el6sat")) flag++;
if (rpm_check(release:"RHEL6", reference:"spacewalk-sniglets-1.2.7-20.el6sat")) flag++;
if (rpm_check(release:"RHEL6", reference:"spacewalk-taskomatic-1.2.39-98.el6sat")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
