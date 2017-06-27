#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0070 and 
# CentOS Errata and Security Advisory 2012:0070 respectively.
#

include("compat.inc");

if (description)
{
  script_id(57734);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/26 15:53:26 $");

  script_cve_id("CVE-2011-3009", "CVE-2011-4815");
  script_bugtraq_id(49126, 51198);
  script_osvdb_id(74841, 78118);
  script_xref(name:"RHSA", value:"2012:0070");

  script_name(english:"CentOS 4 / 5 : ruby (CESA-2012:0070)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ruby packages that fix two security issues are now available
for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Ruby is an extensible, interpreted, object-oriented, scripting
language. It has features to process text files and to do system
management tasks.

A denial of service flaw was found in the implementation of
associative arrays (hashes) in Ruby. An attacker able to supply a
large number of inputs to a Ruby application (such as HTTP POST
request parameters sent to a web application) that are used as keys
when inserting data into an array could trigger multiple hash function
collisions, making array operations take an excessive amount of CPU
time. To mitigate this issue, randomization has been added to the hash
function to reduce the chance of an attacker successfully causing
intentional collisions. (CVE-2011-4815)

It was found that Ruby did not reinitialize the PRNG (pseudorandom
number generator) after forking a child process. This could eventually
lead to the PRNG returning the same result twice. An attacker keeping
track of the values returned by one child process could use this flaw
to predict the values the PRNG would return in other child processes
(as long as the parent process persisted). (CVE-2011-3009)

Red Hat would like to thank oCERT for reporting CVE-2011-4815. oCERT
acknowledges Julian Walde and Alexander Klink as the original
reporters of CVE-2011-4815.

All users of ruby are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-January/018394.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1db12b2d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-January/018401.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cac18240"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"irb-1.8.1-18.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"irb-1.8.1-18.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ruby-1.8.1-18.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ruby-1.8.1-18.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ruby-devel-1.8.1-18.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ruby-devel-1.8.1-18.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ruby-docs-1.8.1-18.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ruby-docs-1.8.1-18.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ruby-libs-1.8.1-18.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ruby-libs-1.8.1-18.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ruby-mode-1.8.1-18.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ruby-mode-1.8.1-18.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ruby-tcltk-1.8.1-18.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ruby-tcltk-1.8.1-18.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"ruby-1.8.5-22.el5_7.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-devel-1.8.5-22.el5_7.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-docs-1.8.5-22.el5_7.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-irb-1.8.5-22.el5_7.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-libs-1.8.5-22.el5_7.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-mode-1.8.5-22.el5_7.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-rdoc-1.8.5-22.el5_7.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-ri-1.8.5-22.el5_7.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-tcltk-1.8.5-22.el5_7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
