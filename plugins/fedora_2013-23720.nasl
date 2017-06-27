#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-23720.
#

include("compat.inc");

if (description)
{
  script_id(71639);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/19 21:47:14 $");

  script_cve_id("CVE-2013-2298", "CVE-2013-7386");
  script_bugtraq_id(59539);
  script_xref(name:"FEDORA", value:"2013-23720");

  script_name(english:"Fedora 19 : boinc-client-7.2.33-2.git1994cc8.fc19 (2013-23720)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"*Updates Boinc to 7.2.33. *Remove the 'Can't connect to boinc-client'
notify at startup. *Fix 'GPU not detected' problem. *Fix security
vulnerability #957811

**Please note for 'GPU not detected' bug** If you still have this
problem after updating, you need to run boinc with your user, not with
boinc user. To do that, add your user to boinc group: 'useradd -G
boinc <your_username>'

Disable boinc daemon: 'systemctl disable boinc-client.service'
'systemctl stop boinc-client.service'

Change directory and files permissions: 'chmod -R g+rw /var/lib/boinc'
'chmod g+rw /var/log/boinc*'

Logout and login again. Now run boinc using this command (under your
user): '/usr/bin/boinc_gpu' If you want to autostart boinc after login
you need to configure your DE to do that. See instruction specific to
your DE on how to do that.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=957771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=957795"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/125128.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6ccc3b59"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected boinc-client package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:boinc-client");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:19");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^19([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 19.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC19", reference:"boinc-client-7.2.33-2.git1994cc8.fc19")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "boinc-client");
}
