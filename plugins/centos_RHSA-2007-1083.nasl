#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:1083 and 
# CentOS Errata and Security Advisory 2007:1083 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(29750);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2007-5947", "CVE-2007-5959", "CVE-2007-5960");
  script_bugtraq_id(26385, 26589, 26593);
  script_xref(name:"RHSA", value:"2007:1083");

  script_name(english:"CentOS 4 / 5 : thunderbird (CESA-2007:1083)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated thunderbird packages that fix several security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Mozilla Thunderbird is a standalone mail and newsgroup client.

A cross-site scripting flaw was found in the way Thunderbird handled
the jar: URI scheme. It may be possible for a malicious HTML mail
message to leverage this flaw, and conduct a cross-site scripting
attack against a user running Thunderbird. (CVE-2007-5947)

Several flaws were found in the way Thunderbird processed certain
malformed HTML mail content. A HTML mail message containing malicious
content could cause Thunderbird to crash, or potentially execute
arbitrary code as the user running Thunderbird. (CVE-2007-5959)

A race condition existed when Thunderbird set the 'window.location'
property when displaying HTML mail content. This flaw could allow a
HTML mail message to set an arbitrary Referer header, which may lead
to a Cross-site Request Forgery (CSRF) attack against websites that
rely only on the Referer header for protection. (CVE-2007-5960)

All users of thunderbird are advised to upgrade to these updated
packages, which contain backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014547.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?60a427cb"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014548.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?455b6a9b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014552.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f0d2ca95"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014557.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5443a106"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014558.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ea4cea2e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22, 79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"thunderbird-1.5.0.12-7.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"thunderbird-1.5.0.12-7.el5.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
