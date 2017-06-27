#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0651. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63949);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/05/02 17:31:16 $");

  script_cve_id("CVE-2010-2792", "CVE-2010-2794");
  script_osvdb_id(67619);
  script_xref(name:"RHSA", value:"2010:0651");

  script_name(english:"RHEL 5 : spice-xpi (RHSA-2010:0651)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated spice-xpi package that fixes two security issues and three
bugs is now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The Simple Protocol for Independent Computing Environments (SPICE) is
a remote display protocol used in Red Hat Enterprise Linux for viewing
virtualized guests running on the Kernel-based Virtual Machine (KVM)
hypervisor, or on Red Hat Enterprise Virtualization Hypervisor.

The spice-xpi package provides a plug-in that allows the SPICE client
to run from within Mozilla Firefox.

A race condition was found in the way the SPICE Firefox plug-in and
the SPICE client communicated. A local attacker could use this flaw to
trick the plug-in and the SPICE client into communicating over an
attacker-controlled socket, possibly gaining access to authentication
details, or resulting in a man-in-the-middle attack on the SPICE
connection. (CVE-2010-2792)

It was found that the SPICE Firefox plug-in used a predictable name
for its log file. A local attacker could use this flaw to conduct a
symbolic link attack, allowing them to overwrite arbitrary files
accessible to the user running Firefox. (CVE-2010-2794)

This update also fixes the following bugs :

* a bug prevented users of Red Hat Enterprise Linux 5.5, with all
updates applied, from running the SPICE Firefox plug-in when using
Firefox 3.6.4. With this update, the plug-in works correctly with
Firefox 3.6.4 and the latest version in Red Hat Enterprise Linux 5.5,
Firefox 3.6.7. (BZ#618244)

* unused code has been removed during source code refactoring. This
also resolves a bug in the SPICE Firefox plug-in that caused it to
close random file descriptors. (BZ#594006, BZ#619067)

Note: This update should be installed together with the RHSA-2010:0632
qspice-client update:
https://rhn.redhat.com/errata/RHSA-2010-0632.html

Users of spice-xpi should upgrade to this updated package, which
contains backported patches to correct these issues. After installing
the update, Firefox must be restarted for the changes to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-2792.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-2794.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0651.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected spice-xpi package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spice-xpi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/25");
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
if (rpm_check(release:"RHEL5", cpu:"i386", reference:"spice-xpi-2.2-2.3.el5_5")) flag++;
if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"spice-xpi-2.2-2.3.el5_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
