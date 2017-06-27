#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-11756.
#

include("compat.inc");

if (description)
{
  script_id(61615);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/20 22:25:11 $");

  script_cve_id("CVE-2012-3361", "CVE-2012-3447");
  script_bugtraq_id(54278, 54869);
  script_xref(name:"FEDORA", value:"2012-11756");

  script_name(english:"Fedora 17 : openstack-nova-2012.1.1-15.fc17 (2012-11756)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fix package dependencies for updates

    - Fix CA cert permissions issue introduced in
      2012.1.1-10

    - Split out into more sub packages

    - Update from stable upstream including...

  - Fix metadata file injection with xen

    - Fix affinity filters when hints is None

    - Fix marker behavior for flavors

    - Handle local remote exceptions consistently

    - Fix qcow2 size on libvirt live block migration

    - Fix for API listing of os hosts

    - Avoid lazy loading errors on instance_type

    - Avoid casts in network manager to prevent races

    - Conditionally allow queries for deleted flavours

    - Fix wrong regex in cleanup_file_locks

    - Add net rules to VMs on compute service start

    - Tolerate parsing null connection info in BDM

    - Support EC2 CreateImage API for boot from volume

    - EC2 DescribeImages reports correct rootDeviceType

    - Reject EC2 CreateImage for instance store

    - Fix EC2 CreateImage no_reboot logic

    - Convert remaining network API casts to calls

    - Move where the fixed ip deallocation happens

    - Fix the qpid_heartbeat option so that it's effective

    - Prohibit host file corruption through file injection
      (CVE-2012-3447)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=846624"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-August/085365.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ea538344"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openstack-nova package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openstack-nova");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:17");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/22");
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
if (! ereg(pattern:"^17([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 17.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC17", reference:"openstack-nova-2012.1.1-15.fc17")) flag++;


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
