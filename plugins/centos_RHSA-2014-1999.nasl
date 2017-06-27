#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1999 and 
# CentOS Errata and Security Advisory 2014:1999 respectively.
#

include("compat.inc");

if (description)
{
  script_id(80056);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/04 14:39:53 $");

  script_cve_id("CVE-2004-2771", "CVE-2014-7844");
  script_bugtraq_id(71701, 71704);
  script_osvdb_id(115954);
  script_xref(name:"RHSA", value:"2014:1999");

  script_name(english:"CentOS 6 / 7 : mailx (CESA-2014:1999)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mailx packages that fix two security issues are now available
for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The mailx packages contain a mail user agent that is used to manage
mail using scripts.

A flaw was found in the way mailx handled the parsing of email
addresses. A syntactically valid email address could allow a local
attacker to cause mailx to execute arbitrary shell commands through
shell meta-characters and the direct command execution functionality.
(CVE-2004-2771, CVE-2014-7844)

Note: Applications using mailx to send email to addresses obtained
from untrusted sources will still remain vulnerable to other attacks
if they accept email addresses which start with '-' (so that they can
be confused with mailx options). To counteract this issue, this update
also introduces the '--' option, which will treat the remaining
command line arguments as email addresses.

All mailx users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-December/020836.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8b7283de"
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-December/020837.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?037e6067"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected mailx package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mailx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"mailx-12.4-8.el6_6")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mailx-12.5-12.el7_0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
