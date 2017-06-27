#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0565 and 
# CentOS Errata and Security Advisory 2017:0565 respectively.
#

include("compat.inc");

if (description)
{
  script_id(97950);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/28 13:31:41 $");

  script_cve_id("CVE-2015-8869");
  script_osvdb_id(137809);
  script_xref(name:"RHSA", value:"2017:0565");

  script_name(english:"CentOS 6 : ocaml (CESA-2017:0565)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for ocaml is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

OCaml is a high-level, strongly-typed, functional, and object-oriented
programming language from the ML family of languages. The ocaml
packages contain two batch compilers (a fast bytecode compiler and an
optimizing native-code compiler), an interactive top level system,
parsing tools (Lex, Yacc, Camlp4), a replay debugger, a documentation
generator, and a comprehensive library.

Security Fix(es) :

* An integer conversion flaw was found in the way OCaml's String
handled its length. Certain operations on an excessively long String
could trigger a buffer overflow or result in an information leak.
(CVE-2015-8869)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 6.9 Release Notes and Red Hat Enterprise Linux 6.9
Technical Notes linked from the References section."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2017-March/003864.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f0e8bc43"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ocaml packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-camlp4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-camlp4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-labltk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-labltk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-ocamldoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"ocaml-3.11.2-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ocaml-camlp4-3.11.2-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ocaml-camlp4-devel-3.11.2-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ocaml-docs-3.11.2-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ocaml-emacs-3.11.2-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ocaml-labltk-3.11.2-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ocaml-labltk-devel-3.11.2-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ocaml-ocamldoc-3.11.2-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ocaml-runtime-3.11.2-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ocaml-source-3.11.2-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ocaml-x11-3.11.2-5.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
