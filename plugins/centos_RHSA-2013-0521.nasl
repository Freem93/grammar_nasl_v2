#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0521 and 
# CentOS Errata and Security Advisory 2013:0521 respectively.
#

include("compat.inc");

if (description)
{
  script_id(65152);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/11/12 17:08:53 $");

  script_cve_id("CVE-2011-3148", "CVE-2011-3149");
  script_bugtraq_id(50343);
  script_osvdb_id(76625, 76626);
  script_xref(name:"RHSA", value:"2013:0521");

  script_name(english:"CentOS 6 : pam (CESA-2013:0521)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pam packages that fix two security issues, several bugs, and
add various enhancements are now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Pluggable Authentication Modules (PAM) provide a system whereby
administrators can set up authentication policies without having to
recompile programs to handle authentication.

A stack-based buffer overflow flaw was found in the way the pam_env
module parsed users' '~/.pam_environment' files. If an application's
PAM configuration contained 'user_readenv=1' (this is not the
default), a local attacker could use this flaw to crash the
application or, possibly, escalate their privileges. (CVE-2011-3148)

A denial of service flaw was found in the way the pam_env module
expanded certain environment variables. If an application's PAM
configuration contained 'user_readenv=1' (this is not the default), a
local attacker could use this flaw to cause the application to enter
an infinite loop. (CVE-2011-3149)

Red Hat would like to thank Kees Cook of the Google ChromeOS Team for
reporting the CVE-2011-3148 and CVE-2011-3149 issues.

These updated pam packages include numerous bug fixes and
enhancements. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 6.4
Technical Notes, linked to in the References, for information on the
most significant of these changes.

All pam users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues and add these
enhancements."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-March/019462.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?93b1b2da"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-February/000653.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?49abf0bf"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected pam packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pam-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"pam-1.1.1-13.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"pam-devel-1.1.1-13.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
