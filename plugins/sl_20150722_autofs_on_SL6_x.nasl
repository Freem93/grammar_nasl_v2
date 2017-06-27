#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(85189);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/08/04 14:00:09 $");

  script_cve_id("CVE-2014-8169");

  script_name(english:"Scientific Linux Security Update : autofs on SL6.x i386/x86_64");
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
"It was found that program-based automounter maps that used interpreted
languages such as Python would use standard environment variables to
locate and load modules of those languages. A local attacker could
potentially use this flaw to escalate their privileges on the system.
(CVE-2014-8169)

Note: This issue has been fixed by adding the 'AUTOFS_' prefix to the
affected environment variables so that they are not used to subvert
the system. A configuration option ('force_standard_program_map_env')
to override this prefix and to use the environment variables without
the prefix has been added. In addition, warnings have been added to
the manual page and to the installed configuration file. Now, by
default the standard variables of the program map are provided only
with the prefix added to its name.

Bug fixes :

  - If the 'ls *' command was executed before a valid mount,
    the autofs program failed on further mount attempts
    inside the mount point, whether the mount point was
    valid or not. While attempting to mount, the 'ls *'
    command of the root directory of an indirect mount was
    executed, which led to an attempt to mount '*', causing
    it to be added to the negative map entry cache. This bug
    has been fixed by checking for and not adding '*' while
    updating the negative map entry cache.

  - The autofs program by design did not mount host map
    entries that were duplicate exports in an NFS server
    export list. The duplicate entries in a multi-mount map
    entry were recognized as a syntax error and autofs
    refused to perform mounts when the duplicate entries
    occurred. Now, autofs has been changed to continue
    mounting the last seen instance of the duplicate entry
    rather than fail, and to report the problem in the log
    files to alert the system administrator.

  - The autofs program did not recognize the yp map type in
    the master map. This was caused by another change in the
    master map parser to fix a problem with detecting the
    map format associated with mapping the type in the
    master map. The change led to an incorrect length for
    the type comparison of yp maps that resulted in a match
    operation failure. This bug has been fixed by correcting
    the length which is used for the comparison.

  - The autofs program did not update the export list of the
    Sun-format maps of the network shares exported from an
    NFS server. This happened due to a change of the
    Sun-format map parser leading to the hosts map update to
    stop working on the map re-read operation. The bug has
    been now fixed by selectively preventing this type of
    update only for the Sun-formatted maps. The updates of
    the export list on the Sun-format maps are now visible
    and refreshing of the export list is no longer supported
    for the Sun-formatted hosts map.

  - Within changes made for adding of the Sun-format maps,
    an incorrect check was added that caused a segmentation
    fault in the Sun-format map parser in certain
    circumstances. This has been now fixed by analyzing the
    intent of the incorrect check and changing it in order
    to properly identify the conditions without causing a
    fault.

  - A bug in the autofs program map lookup module caused an
    incorrect map format type comparison. The incorrect
    comparison affected the Sun-format program maps where it
    led to the unused macro definitions. The bug in the
    comparison has been fixed so that the macro definitions
    are not present for the Sun-format program maps."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1508&L=scientific-linux-errata&F=&S=&P=6876
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c091f68"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected autofs and / or autofs-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"autofs-5.0.5-113.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autofs-debuginfo-5.0.5-113.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
