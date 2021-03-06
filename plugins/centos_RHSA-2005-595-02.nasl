#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:595 and 
# CentOS Errata and Security Advisory 2005:595-02 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67029);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-1769", "CVE-2005-2095");
  script_bugtraq_id(13973, 14254);
  script_osvdb_id(17360, 17361, 17873, 17874);
  script_xref(name:"RHSA", value:"2005:595");

  script_name(english:"CentOS 3 / 4 : SquirrelMail (CESA-2005:595-02)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated squirrelmail package that fixes two security issues is now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

[Updated 04 Aug 2005] The previous SquirrelMail package released with
this errata contained a bug which rendered the addressbook unusable.
The erratum has been updated with a package which corrects this issue.

SquirrelMail is a standards-based webmail package written in PHP4.

A bug was found in the way SquirrelMail handled the $_POST variable.
If a user is tricked into visiting a malicious URL, the user's
SquirrelMail preferences could be read or modified. The Common
Vulnerabilities and Exposures project assigned the name CVE-2005-2095
to this issue.

Several cross-site scripting bugs were discovered in SquirrelMail. An
attacker could inject arbitrary JavaScript or HTML content into
SquirrelMail pages by tricking a user into visiting a carefully
crafted URL, or by sending them a carefully constructed HTML email
message. The Common Vulnerabilities and Exposures project assigned the
name CVE-2005-1769 to this issue.

All users of SquirrelMail should upgrade to this updated package,
which contains backported patches that resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012006.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85906e11"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012007.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4ed275f3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012012.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66b92db3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012013.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?51fc916f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squirrelmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squirrelmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"squirrelmail-1.4.3a-11.EL3.centos.1")) flag++;

if (rpm_check(release:"CentOS-4", reference:"squirrelmail-1.4.3a-12.EL4.centos4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
