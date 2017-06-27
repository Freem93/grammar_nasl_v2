#
# (C) Tenable Network Security, Inc.
#
# Disabled on 2013/07/05.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0102. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64025);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/05/02 18:01:07 $");

  script_cve_id("CVE-2012-0059");
  script_bugtraq_id(51569);
  script_osvdb_id(78359);
  script_xref(name:"RHSA", value:"2012:0102");

  script_name(english:"RHEL 5 / 6 : spacewalk-backend (RHSA-2012:0102)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated spacewalk-backend packages that fix one security issue are now
available for Red Hat Network Proxy 5.4.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Red Hat Network (RHN) Proxy provides a mechanism for caching content,
such as package updates from Red Hat or custom content created for an
organization on an internal, centrally-located server.

If a user submitted a system registration XML-RPC call to an RHN Proxy
server (for example, by running 'rhnreg_ks') and that call failed,
their RHN user password was included in plain text in the error
messages both stored in the server log and mailed to the server
administrator. With this update, user passwords are excluded from
these error messages to avoid the exposure of authentication
credentials. (CVE-2012-0059)

Users of Red Hat Network Proxy are advised to upgrade to these updated
packages, which correct this issue. For this update to take effect,
Red Hat Network Proxy must be restarted. Refer to the Solution section
for details."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0059.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0102.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected spacewalk-backend and / or spacewalk-backend-libs
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}

# Deprecated
exit(0, "This plugin has been temporarily deprecated.");

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
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-1.2.13-66.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-libs-1.2.13-66.el5sat")) flag++;

if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-1.2.13-66.el6sat")) flag++;
if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-libs-1.2.13-66.el6sat")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
