#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-11103.
#

include("compat.inc");

if (description)
{
  script_id(55955);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/11 13:24:19 $");

  script_cve_id("CVE-2011-1598", "CVE-2011-1748", "CVE-2011-2183", "CVE-2011-2213", "CVE-2011-2484", "CVE-2011-2497", "CVE-2011-2517", "CVE-2011-2695", "CVE-2011-2699", "CVE-2011-2905");
  script_bugtraq_id(47503, 47835, 48333, 48383, 48472, 48538, 48697, 48802, 49140);
  script_osvdb_id(71884, 73040, 73451, 74123, 74634, 74653, 74658, 74678, 74679, 74680);
  script_xref(name:"FEDORA", value:"2011-11103");

  script_name(english:"Fedora 14 : kernel-2.6.35.14-95.fc14 (2011-11103)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to kernel 2.6.35.14 :

http://ftp.kernel.org/pub/linux/kernel/v2.6/longterm/v2.6.35/ChangeLog
-2.6.35.14

NOTE: These upstream commits from 2.6.35.14 were already in the
previous Fedora 14 kernel 2.6.35.13-92 :

b934c20de1398d4a82d2ecfeb588a214a910f13f
3cd01976e702ccaffb907727caff4f8789353599
9c047157a20521cd525527947b13b950d168d2e6
6b4e81db2552bad04100e7d5ddeed7e848f53b48
3e9d08ec0a68f6faf718d5a7e050fe5ca0ba004f
b522f02184b413955f3bc952e3776ce41edc6355
194b3da873fd334ef183806db751473512af29ce
a1f74ae82d133ebb2aabb19d181944b4e83e9960
e9cdd343a5e42c43bcda01e609fa23089e026470
14fb57dccb6e1defe9f89a66f548fcb24c374c1d
221d1d797202984cb874e3ed9f1388593d34ee22
a294865978b701e4d0d90135672749531b9a900d

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://ftp.kernel.org/pub/linux/kernel/v2.6/longterm/v2.6.35/ChangeLog-2.6.35.14
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?13012155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=698057"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=710338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=714536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=715436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=716805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=718152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=722557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=723429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=729808"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-August/064393.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?38ec6e06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel package."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^14([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 14.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC14", reference:"kernel-2.6.35.14-95.fc14")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
