#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0016 and 
# CentOS Errata and Security Advisory 2012:0016 respectively.
#

include("compat.inc");

if (description)
{
  script_id(57486);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/28 18:05:37 $");

  script_cve_id("CVE-2011-0216", "CVE-2011-2834", "CVE-2011-3905", "CVE-2011-3919");
  script_osvdb_id(73994, 75560, 77707, 78148);
  script_xref(name:"RHSA", value:"2012:0016");

  script_name(english:"CentOS 4 : libxml2 (CESA-2012:0016)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libxml2 packages that fix several security issues are now
available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The libxml2 library is a development toolbox providing the
implementation of various XML standards. One of those standards is the
XML Path Language (XPath), which is a language for addressing parts of
an XML document.

A heap-based buffer overflow flaw was found in the way libxml2 decoded
entity references with long names. A remote attacker could provide a
specially crafted XML file that, when opened in an application linked
against libxml2, would cause the application to crash or, potentially,
execute arbitrary code with the privileges of the user running the
application. (CVE-2011-3919)

An off-by-one error, leading to a heap-based buffer overflow, was
found in the way libxml2 parsed certain XML files. A remote attacker
could provide a specially crafted XML file that, when opened in an
application linked against libxml2, would cause the application to
crash or, potentially, execute arbitrary code with the privileges of
the user running the application. (CVE-2011-0216)

A flaw was found in the way libxml2 parsed certain XPath expressions.
If an attacker were able to supply a specially crafted XML file to an
application using libxml2, as well as an XPath expression for that
application to run against the crafted file, it could cause the
application to crash. (CVE-2011-2834)

Note: Red Hat does not ship any applications that use libxml2 in a way
that would allow the CVE-2011-2834 flaw to be exploited; however,
third-party applications may allow XPath expressions to be passed
which could trigger this flaw.

An out-of-bounds memory read flaw was found in libxml2. A remote
attacker could provide a specially crafted XML file that, when opened
in an application linked against libxml2, would cause the application
to crash. (CVE-2011-3905)

All users of libxml2 are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The desktop
must be restarted (log out, then log back in) for this update to take
effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-January/018369.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed1bef90"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/12");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libxml2-2.6.16-12.9")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libxml2-2.6.16-12.9")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libxml2-devel-2.6.16-12.9")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libxml2-devel-2.6.16-12.9")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libxml2-python-2.6.16-12.9")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libxml2-python-2.6.16-12.9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
