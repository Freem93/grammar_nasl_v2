#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61131);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2011-2911");

  script_name(english:"Scientific Linux Security Update : gstreamer-plugins on SL4.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The gstreamer-plugins packages contain plug-ins used by the GStreamer
streaming-media framework to support a wide variety of media formats.

An integer overflow flaw, a boundary error, and multiple off-by-one
flaws were found in various ModPlug music file format library
(libmodplug) modules, embedded in GStreamer. An attacker could create
specially crafted music files that, when played by a victim, would
cause applications using GStreamer to crash or, potentially, execute
arbitrary code. (CVE-2011-2911, CVE-2011-2912, CVE-2011-2913,
CVE-2011-2914, CVE-2011-2915)

All users of gstreamer-plugins are advised to upgrade to these updated
packages, which contain backported patches to correct these issues.
After installing the update, all applications using GStreamer (such as
Rhythmbox) must be restarted for the changes to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1109&L=scientific-linux-errata&T=0&P=1260
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2c436fad"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected gstreamer-plugins, gstreamer-plugins-debuginfo and
/ or gstreamer-plugins-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL4", reference:"gstreamer-plugins-0.8.5-1.EL.4")) flag++;
if (rpm_check(release:"SL4", reference:"gstreamer-plugins-debuginfo-0.8.5-1.EL.4")) flag++;
if (rpm_check(release:"SL4", reference:"gstreamer-plugins-devel-0.8.5-1.EL.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
