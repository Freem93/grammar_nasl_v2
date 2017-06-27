#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1603 and 
# CentOS Errata and Security Advisory 2013:1603 respectively.
#

include("compat.inc");

if (description)
{
  script_id(79165);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/26 15:53:26 $");

  script_cve_id("CVE-2013-4481", "CVE-2013-4482");
  script_bugtraq_id(63854, 63859);
  script_osvdb_id(100078, 100079);
  script_xref(name:"RHSA", value:"2013:1603");

  script_name(english:"CentOS 6 : luci (CESA-2013:1603)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated luci packages that fix two security issues, several bugs, and
add two enhancements are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Luci is a web-based high availability administration application.

A flaw was found in the way the luci service was initialized. If a
system administrator started the luci service from a directory that
was writable to by a local user, that user could use this flaw to
execute arbitrary code as the root or luci user. (CVE-2013-4482)

A flaw was found in the way luci generated its configuration file. The
file was created as world readable for a short period of time,
allowing a local user to gain access to the authentication secrets
stored in the configuration file. (CVE-2013-4481)

These issues were discovered by Jan Pokorny of Red Hat.

These updated luci packages include numerous bug fixes and two
enhancements. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 6.5
Technical Notes, linked to in the References, for information on the
most significant of these changes.

All luci users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues and add these
enhancements. After installing this update, the luci service will be
restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-November/001004.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5db2ea3e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected luci package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:luci");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");
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
if (rpm_check(release:"CentOS-6", reference:"luci-0.26.0-48.el6.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
