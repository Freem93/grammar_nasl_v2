#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0706 and 
# CentOS Errata and Security Advisory 2016:0706 respectively.
#

include("compat.inc");

if (description)
{
  script_id(90837);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2016-3068", "CVE-2016-3069");
  script_osvdb_id(136451, 136452);
  script_xref(name:"RHSA", value:"2016:0706");

  script_name(english:"CentOS 7 : mercurial (CESA-2016:0706)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for mercurial is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Mercurial is a fast, lightweight source control management system
designed for efficient handling of very large distributed projects.

Security Fix(es) :

* It was discovered that Mercurial failed to properly check Git
sub-repository URLs. A Mercurial repository that includes a Git
sub-repository with a specially crafted URL could cause Mercurial to
execute arbitrary code. (CVE-2016-3068)

* It was discovered that the Mercurial convert extension failed to
sanitize special characters in Git repository names. A Git repository
with a specially crafted name could cause Mercurial to execute
arbitrary code when the Git repository was converted to a Mercurial
repository. (CVE-2016-3069)

Red Hat would like to thank Blake Burkhart for reporting these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2016-May/021855.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mercurial packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:emacs-mercurial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:emacs-mercurial-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mercurial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mercurial-hgk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"emacs-mercurial-2.6.2-6.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"emacs-mercurial-el-2.6.2-6.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mercurial-2.6.2-6.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mercurial-hgk-2.6.2-6.el7_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
