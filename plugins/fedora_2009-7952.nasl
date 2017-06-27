#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-7952.
#

include("compat.inc");

if (description)
{
  script_id(40357);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/21 22:50:38 $");

  script_bugtraq_id(35757);
  script_xref(name:"FEDORA", value:"2009-7952");

  script_name(english:"Fedora 11 : znc-0.072-3.fc11 (2009-7952)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"No CVE yet, one has been requested. Upgrade to 0.072 of ZNC, fixes
security issue in bug 513152 An users data directory traversal flaw
was found in the way ZNC used to handle file upload requests via
Direct Client Connection (DCC) /dcc SEND messages. A remote IRC user
could issue a /dcc SEND message with a specially crafted content (file
to upload), which once accepted by a local, unsuspecting ZNC user,
would overwrite relevant files in the users/<user>/downloads data
directory.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=513152"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026911.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6147dfe6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected znc package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:znc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^11([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 11.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC11", reference:"znc-0.072-3.fc11")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "znc");
}
