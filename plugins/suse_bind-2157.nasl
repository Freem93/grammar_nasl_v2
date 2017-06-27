#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29385);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2012/12/27 12:42:24 $");

  script_xref(name:"CERT", value:"697164");
  script_xref(name:"CERT", value:"915404");

  script_name(english:"SuSE 10 Security Update : bind (ZYPP Patch Number 2157)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes two vulnerabilities in bind that allow a remote
attacker to trigger a denial-of-service attack. (VU#697164 - BIND
INSIST failure due to excessive recursive queries, VU#915404 - BIND
assertion failure during SIG query processing.)"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 2157.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/27");
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
if (rpm_check(release:"SLED10", sp:0, reference:"bind-libs-9.3.2-17.8")) flag++;
if (rpm_check(release:"SLED10", sp:0, cpu:"x86_64", reference:"bind-libs-32bit-9.3.2-17.8")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"bind-9.3.2-17.8")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"bind-devel-9.3.2-17.8")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"bind-libs-9.3.2-17.8")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"bind-libs-32bit-9.3.2-17.8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
