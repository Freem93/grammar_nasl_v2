#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-10459.
#

include("compat.inc");

if (description)
{
  script_id(84477);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/10/19 22:49:04 $");

  script_xref(name:"FEDORA", value:"2015-10459");

  script_name(english:"Fedora 22 : cups-x2go-3.0.1.3-1.fc22 (2015-10459)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - New upstream version (3.0.1.2) :

    - cups-x2go{,.conf}: port to File::Temp. Use
      Text::ParseWords to split up the ps2pdf command line
      correctly. Don't use system() but IPC::Open2::open2().
      Capture the ps2pdf program's stdout and write it to
      the temporary file handle 'manually'. Should fix
      problems reported by Jan Bi on IRC.

    - cups-x2go: fix commented out second ps2pdf definition
      to output PDF data to stdout.

    - New upstream version (3.0.1.3) :

    - cups-x2go: import tempfile() function from File::Temp
      module.

    - cups-x2go: only repeat the last X, not the whole
      '.pdfX' string (or the like.)

    - cups-x2go: actually print 'real' executed command
      instead of the 'original' one with placeholders.

    - cups-x2go: read output from ghostscript, don't write a
      filehandle to the temporary file. Fixes a hanging
      ghostscript call and... well... random junk, instead
      of a 'real' PDF file.

    - cups-x2go: use parentheses around function arguments.

    - cups-x2go: fix binmode() call, :raw layer is implicit.

    - cups-x2go: fix print call... Does not allow to
      separate parameters with a comma.

    - cups-x2go: add correct :raw layer to binmode calls.

    - cups-x2go: fix tiny typo.

    - cups-x2go: read data from GS and STDIN in chunks of 8
      kbytes, instead of everything at once. Handles large
      print jobs gracefully.

    - cups-x2go: add parentheses to close() calls.

    - cups-x2go: delete PDF and title temporary files
      automatically.

    - cups-x2go: unlink PS temporary file on-demand in END
      block. Also move closelog to END block, because we
      want to print diagnosis messages in the END block.

    - cups-x2go: don't use unlink() explicitly. Trust
      File::Temp and our END block to clean up correctly.

    - cups-x2go: there is no continue in perl for stepping
      forward a loop. Still not. I keep forgetting that. Use
      next. (Partly) Fixes: #887.

    - cups-x2go: use the same temp file template for PS, PDF
      and title files. Use appropriate suffixes if necessary
      when generating PDF and title temp files. (Fully)
      Fixes: #887. Update to 3.0.1.1 :

  - Add a short README that provides some getting started
    information. Update to 3.0.1.1 :

  - Add a short README that provides some getting started
    information.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-June/161146.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e1ae310e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cups-x2go package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:cups-x2go");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^22([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 22.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC22", reference:"cups-x2go-3.0.1.3-1.fc22")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups-x2go");
}
