#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2016-5d6d75dbea.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(90104);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/03/24 14:02:01 $");

  script_cve_id("CVE-2014-1748", "CVE-2015-1071", "CVE-2015-1076", "CVE-2015-1081", "CVE-2015-1083", "CVE-2015-1120", "CVE-2015-1122", "CVE-2015-1127", "CVE-2015-1153", "CVE-2015-1155", "CVE-2015-3658", "CVE-2015-3659", "CVE-2015-3727", "CVE-2015-3731", "CVE-2015-3741", "CVE-2015-3743", "CVE-2015-3745", "CVE-2015-3747", "CVE-2015-3748", "CVE-2015-3749", "CVE-2015-3752", "CVE-2015-5788", "CVE-2015-5794", "CVE-2015-5801", "CVE-2015-5809", "CVE-2015-5822", "CVE-2015-5928");
  script_xref(name:"FEDORA", value:"2016-5d6d75dbea");

  script_name(english:"Fedora 23 : webkitgtk-2.4.10-1.fc23 (2016-5d6d75dbea)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update addresses the following vulnerabilities :

  - CVE-2015-1120

(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1120)

  - CVE-2015-1076

(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1076)

  - CVE-2015-1071

(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1071)

  - CVE-2015-1081

(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1081)

  - CVE-2015-1122

(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1122)

  - CVE-2015-1155

(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1155)

  - CVE-2014-1748

(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-1748)

  - CVE-2015-3752

(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-3752)

  - CVE-2015-5809

(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5809)

  - CVE-2015-5928

(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5928)

  - CVE-2015-3749

(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-3749)

  - CVE-2015-3659

(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-3659)

  - CVE-2015-3748

(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-3748)

  - CVE-2015-3743

(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-3743)

  - CVE-2015-3731

(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-3731)

  - CVE-2015-3745

(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-3745)

  - CVE-2015-5822

(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5822)

  - CVE-2015-3658

(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-3658)

  - CVE-2015-3741

(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-3741)

  - CVE-2015-3727

(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-3727)

  - CVE-2015-5801

(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5801)

  - CVE-2015-5788

(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5788)

  - CVE-2015-3747

(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-3747)

  - CVE-2015-5794

(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5794)

  - CVE-2015-1127

(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1127)

  - CVE-2015-1153

(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1153)

  - CVE-2015-1083

(https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1083)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-March/179225.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0136964c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected webkitgtk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:webkitgtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:23");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^23([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 23.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC23", reference:"webkitgtk-2.4.10-1.fc23")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "webkitgtk");
}
