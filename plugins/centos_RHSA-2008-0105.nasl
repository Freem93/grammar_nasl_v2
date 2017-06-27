#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0105 and 
# CentOS Errata and Security Advisory 2008:0105 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(30222);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2008-0304", "CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0415", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0420", "CVE-2008-0591", "CVE-2008-0592", "CVE-2008-0593");
  script_bugtraq_id(24293, 27406, 27683, 28012);
  script_xref(name:"RHSA", value:"2008:0105");

  script_name(english:"CentOS 4 / 5 : thunderbird (CESA-2008:0105)");
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

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

[Updated 27th February 2008] The erratum text has been updated to
include the details of additional issues that were fixed by these
erratum packages, but which were not public at the time of release. No
changes have been made to the packages.

Mozilla Thunderbird is a standalone mail and newsgroup client.

A heap-based buffer overflow flaw was found in the way Thunderbird
processed messages with external-body Multipurpose Internet Message
Extensions (MIME) types. A HTML mail message containing malicious
content could cause Thunderbird to execute arbitrary code as the user
running Thunderbird. (CVE-2008-0304)

Several flaws were found in the way Thunderbird processed certain
malformed HTML mail content. A HTML mail message containing malicious
content could cause Thunderbird to crash, or potentially execute
arbitrary code as the user running Thunderbird. (CVE-2008-0412,
CVE-2008-0413, CVE-2008-0415, CVE-2008-0419)

Several flaws were found in the way Thunderbird displayed malformed
HTML mail content. A HTML mail message containing specially crafted
content could trick a user into surrendering sensitive information.
(CVE-2008-0420, CVE-2008-0591, CVE-2008-0593)

A flaw was found in the way Thunderbird handles certain chrome URLs.
If a user has certain extensions installed, it could allow a malicious
HTML mail message to steal sensitive session data. Note: this flaw
does not affect a default installation of Thunderbird. (CVE-2008-0418)

Note: JavaScript support is disabled by default in Thunderbird; the
above issues are not exploitable unless JavaScript is enabled.

A flaw was found in the way Thunderbird saves certain text files. If a
remote site offers a file of type 'plain/text', rather than
'text/plain', Thunderbird will not show future 'text/plain' content to
the user, forcing them to save those files locally to view the
content. (CVE-2008-0592)

Users of thunderbird are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014665.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2d75fd09"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014666.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a6589f8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014671.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1916ee59"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014672.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c774c7c5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014676.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a89ca574"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 79, 119, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"thunderbird-1.5.0.12-8.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"thunderbird-1.5.0.12-8.el5.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
