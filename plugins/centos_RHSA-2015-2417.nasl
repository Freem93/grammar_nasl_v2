#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2417 and 
# CentOS Errata and Security Advisory 2015:2417 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(87158);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/04/28 18:15:07 $");

  script_cve_id("CVE-2014-8169");
  script_osvdb_id(118991);
  script_xref(name:"RHSA", value:"2015:2417");

  script_name(english:"CentOS 7 : autofs (CESA-2015:2417)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated autofs packages that fix one security issue, several bugs, and
add one enhancement are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The autofs utility controls the operation of the automount daemon. The
daemon automatically mounts file systems when in use and unmounts them
when they are not busy.

It was found that program-based automounter maps that used interpreted
languages such as Python used standard environment variables to locate
and load modules of those languages. A local attacker could
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

Red Hat would like to thank the Georgia Institute of Technology for
reporting this issue.

Notably, this update fixes the following bugs :

* When the 'ls *' command was run in the root of an indirect mount,
autofs attempted to literally mount the wildcard character (*) causing
it to be added to the negative cache. If done before a valid mount,
autofs then failed on further mount attempts inside the mount point,
valid or not. This has been fixed, and wildcard map entries now
function in the described situation. (BZ#1166457)

* When autofs encountered a syntax error consisting of a duplicate
entry in a multimap entry, it reported an error and did not mount the
map entry. With this update, autofs has been amended to report the
problem in the log to alert the system administrator and use the last
seen instance of the duplicate entry rather than fail. (BZ#1205600)

* In the ldap and sss lookup modules, the map reading functions did
not distinguish between the 'no entry found' and 'service not
available' errors. Consequently, when the 'service not available'
response was returned from a master map read, autofs did not update
the mounts. An 'entry not found' return does not prevent the map
update, so the ldap and sss lookup modules were updated to distinguish
between these two returns and now work as expected. (BZ#1233065)

In addition, this update adds the following enhancement :

* The description of the configuration parameter map_hash_table_size
was missing from the autofs.conf(5) man page and its description in
the configuration file comments was insufficient. A description of the
parameter has been added to autofs.conf(5), and the configuration file
comments have been updated. (BZ#1238573)

All autofs users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add this
enhancement."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-November/002123.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1421fcad"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected autofs package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autofs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autofs-5.0.7-54.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
