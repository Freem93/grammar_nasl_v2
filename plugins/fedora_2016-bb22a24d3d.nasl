#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-bb22a24d3d.
#

include("compat.inc");

if (description)
{
  script_id(96057);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/02/27 15:13:33 $");

  script_cve_id("CVE-2016-8652");
  script_xref(name:"FEDORA", value:"2016-bb22a24d3d");

  script_name(english:"Fedora 24 : 1:dovecot (2016-bb22a24d3d)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fixed crash in auth process when auth-policy was
    configured and authentication was aborted/failed without
    a username set.

  - director: If two users had different tags but the same
    hash, the users may have been redirected to the wrong
    tag's hosts.

  - Index files may have been thought incorrectly lost,
    causing 'Missing middle file seq=..' to be logged and
    index rebuild. This happened more easily with IMAP
    hibernation enabled.

  - Various fixes to restoring state correctly in
    un-hibernation.

  - dovecot.index files were commonly 4 bytes per email too
    large. This is because 3 bytes per email were being
    wasted that could have been used for IMAP keywords.

  - Various fixes to handle dovecot.list.index corruption
    better.

  - lib-fts: Fixed assert-crash in address tokenizer with
    specific input.

  - Fixed assert-crash in HTML to text parsing with specific
    input (e.g. for FTS indexing or snippet generation)

  - doveadm sync -1: Fixed handling mailbox GUID conflicts.

  - sdbox, mdbox: Perform full index rebuild if corruption
    is detected inside lib-index, which runs index fsck.

  - quota: Don't skip quota checks when moving mails between
    different quota roots.

  - search: Multiple sequence sets or UID sets in search
    parameters weren't handled correctly. They were
    incorrectly merged together.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-bb22a24d3d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 1:dovecot package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:1:dovecot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^24([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 24", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC24", reference:"dovecot-2.2.27-1.fc24", epoch:"1")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "1:dovecot");
}
