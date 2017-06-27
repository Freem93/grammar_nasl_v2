#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0921-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83755);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/05/02 15:19:31 $");

  script_cve_id("CVE-2015-0797");
  script_bugtraq_id(74181);
  script_osvdb_id(120789);

  script_name(english:"SUSE SLED11 Security Update : gstreamer-0_10-plugins-bad (SUSE-SU-2015:0921-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"gstreamer-0_10-plugins-bad was updated to fix a security issue, a
buffer overflow in mp4 parsing (bnc#927559 CVE-2015-0797).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927559"
  );
  # https://download.suse.com/patch/finder/?keywords=f7ccd0598b1d14e206c07e76854611ef
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c4b515d3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0797.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150921-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d9ac9fed"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Desktop 11 SP3 :

zypper in -t patch sledsp3-gstreamer-0_10-plugins-bad=10643

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gstreamer-0_10-plugins-bad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gstreamer-0_10-plugins-bad-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstbasecamerabinsrc-0_10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstbasecamerabinsrc-0_10-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstbasevideo-0_10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstbasevideo-0_10-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstphotography-0_10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstphotography-0_10-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstsignalprocessor-0_10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstsignalprocessor-0_10-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstvdp-0_10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstvdp-0_10-0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED11" && (! ereg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"gstreamer-0_10-plugins-bad-0.10.22-7.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"gstreamer-0_10-plugins-bad-lang-0.10.22-7.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libgstbasecamerabinsrc-0_10-0-0.10.22-7.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libgstbasevideo-0_10-0-0.10.22-7.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libgstphotography-0_10-0-0.10.22-7.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libgstsignalprocessor-0_10-0-0.10.22-7.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libgstvdp-0_10-0-0.10.22-7.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libgstbasecamerabinsrc-0_10-0-32bit-0.10.22-7.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libgstbasevideo-0_10-0-32bit-0.10.22-7.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libgstphotography-0_10-0-32bit-0.10.22-7.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libgstsignalprocessor-0_10-0-32bit-0.10.22-7.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libgstvdp-0_10-0-32bit-0.10.22-7.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"gstreamer-0_10-plugins-bad-0.10.22-7.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"gstreamer-0_10-plugins-bad-lang-0.10.22-7.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"libgstbasecamerabinsrc-0_10-0-0.10.22-7.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"libgstbasevideo-0_10-0-0.10.22-7.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"libgstphotography-0_10-0-0.10.22-7.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"libgstsignalprocessor-0_10-0-0.10.22-7.11.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"libgstvdp-0_10-0-0.10.22-7.11.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gstreamer-0_10-plugins-bad");
}
