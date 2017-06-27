#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-9312.
#

include("compat.inc");

if (description)
{
  script_id(47529);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/10/20 21:47:26 $");

  script_cve_id("CVE-2009-4016", "CVE-2010-0300");
  script_bugtraq_id(37978, 37979);
  script_osvdb_id(62151, 62152, 62153);
  script_xref(name:"FEDORA", value:"2010-9312");

  script_name(english:"Fedora 12 : ircd-hybrid-7.2.3-11.fc12 / ircd-ratbox-2.2.8-7.fc12 (2010-9312)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were reported in ircd-hybrid, ircd-ratbox, and
oftc-hybrid. The first is an integer overflow that can lead to a
denial of service or, possibly, the execution of arbitrary code on the
ircd server (CVE-2009-4016 (patch [1])), the second is a NULL pointer
dereference that can lead to a denial of service of the ircd server
(CVE-2010-0300 (patch [2])). This has been corrected in upstream
ircd-ratbox 2.2.9 [3]. CVE-2010-0300 may be ircd- ratbox specific,
however CVE-2009-4016 affects both ircd servers. [1]
http://ircd.ratbox.org/cgi-bin/index.cgi/ircd-
ratbox/branches/RATBOX_3_0/src/cache.c?r1=26334&r2=26732 [2]
http://trac.oftc.net/projects/oftc-hybrid/changeset/1062 [3]
http://lists.ratbox.org/pipermail/ircd-ratbox/2010-January/000891.html

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://ircd.ratbox.org/cgi-bin/index.cgi/ircd-"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.ratbox.org/pipermail/ircd-ratbox/2010-January/000891.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://trac.oftc.net/projects/oftc-hybrid/changeset/1062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=559382"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-June/042574.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3e5c976c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-June/042575.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?355bb8f4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ircd-hybrid and / or ircd-ratbox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ircd-hybrid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ircd-ratbox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^12([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 12.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC12", reference:"ircd-hybrid-7.2.3-11.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"ircd-ratbox-2.2.8-7.fc12")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ircd-hybrid / ircd-ratbox");
}
