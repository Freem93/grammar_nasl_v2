#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29598);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2012/05/17 11:27:19 $");

  script_cve_id("CVE-2006-4799", "CVE-2006-4800");

  script_name(english:"SuSE 10 Security Update : xine-lib (ZYPP Patch Number 2307)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple buffer overflows were fixed in the XINE decoder libraries,
which could be used by attackers to crash players or potentially
execute code.

  - Buffer overflow in ffmpeg for xine-lib before 1.1.2
    might allow context-dependent attackers to execute
    arbitrary code via a crafted AVI file and 'bad indexes'.
    (CVE-2006-4799)

  - Multiple buffer overflows in libavcodec in ffmpeg before
    0.4.9_p20060530 allow remote attackers to cause a denial
    of service or possibly execute arbitrary code via
    multiple unspecified vectors in (1) dtsdec.c, (2)
    vorbis.c, (3) rm.c, (4) sierravmd.c, (5) smacker.c, (6)
    tta.c, (7) 4xm.c, (8) alac.c, (9) cook.c, (10)
    shorten.c, (11) smacker.c, (12) snow.c, and (13) tta.c.
    (CVE-2006-4800)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-4799.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-4800.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 2307.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2012 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:0, reference:"xine-lib-1.1.1-24.10")) flag++;
if (rpm_check(release:"SLED10", sp:0, cpu:"x86_64", reference:"xine-lib-32bit-1.1.1-24.10")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
