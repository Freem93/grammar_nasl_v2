#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-0682.
#

include("compat.inc");

if (description)
{
  script_id(57610);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/20 22:15:25 $");

  script_cve_id("CVE-2011-4596");
  script_bugtraq_id(51047);
  script_xref(name:"FEDORA", value:"2012-0682");

  script_name(english:"Fedora 16 : openstack-nova-2011.3.1-0.4.10818.fc16 (2012-0682)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to 2011.3.1 release candidate. See
https://launchpad.net/nova/+milestone/2011.3.1

This also includes a minor bug fix for libguestfs file injection

This update includes ~50 patches from the upstream stable branch and a
fix for an issue with attaching volumes.

Sync up with Fedora spec, to only add fuse group if present.
Explicitly depend on the fuse package to avoid #767852. Requires
manually installing 'fuse' first.

Also adds libguestfs update

Add --yes, --rootpw, and --novapw arguments to
openstack-nova-db-setup.

Please ensure you have at least python-migrate-0.6-6 installed when
testing this

Change the default database from sqlite to mysql.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=740456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=752709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=767251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://launchpad.net/nova/+milestone/2011.3.1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-January/072190.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb757691"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openstack-nova package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openstack-nova");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:16");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^16([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 16.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC16", reference:"openstack-nova-2011.3.1-0.4.10818.fc16")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openstack-nova");
}
