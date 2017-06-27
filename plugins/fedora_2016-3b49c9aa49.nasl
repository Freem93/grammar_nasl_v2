#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-3b49c9aa49.
#

include("compat.inc");

if (description)
{
  script_id(92083);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/07/14 15:07:58 $");

  script_xref(name:"FEDORA", value:"2016-3b49c9aa49");

  script_name(english:"Fedora 22 : nfdump (2016-3b49c9aa49)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"nfdump 1.6.15 released.

---

  - Fix Security issue
    http://www.security-assessment.com/files/documents/advis
    ory/Nfdump%20nfcapd%201.6.14%20-%20Multiple%20Vulnerabil
    ities.pdf

  - Fix obyte, opps and obps output records

  - Fix wrong bps type case in cvs output. Fix opbs ipbs
    typos

nfdump 1.6.14 released.

---

  - Create libnfdump for dynamic linking

  - Add -R to ModifyCompression

  - Add std sampler ID 4 Bytes and allow random sampler (tag
    50)

  - Add BZ2 compression along existing LZ0

  - Add direct write to flowtools converter ft2nfdump

  - Fix CentOS compile issues with flow-tools converter

  - Fix FreeBSD,OpenBSD build problems

  - Fix timestamp overflow in sflow.c

  - Fix IP Fragmentation in sflow collector

  - Fix compile errors on other platforms

  - Fix zero alignment bug, if only half of an extension is
    sent

  - Fix nfanon time window bug in subsequent files in -R
    list

  - Fix CommonRecordV0Type conversion bug

  - Fix nfexport bug, if only one single map exists

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-3b49c9aa49"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nfdump package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nfdump");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/14");
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
if (! ereg(pattern:"^22([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 22", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC22", reference:"nfdump-1.6.15-1.fc22")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nfdump");
}
